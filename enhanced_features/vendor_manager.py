# enhanced_features/vendor_manager.py
"""Multi-vendor support system for different network OS platforms."""

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class VendorType(Enum):
    """Supported vendor types."""
    CISCO_IOS = "cisco_ios"
    CISCO_XE = "cisco_xe" 
    CISCO_XR = "cisco_xr"
    CISCO_NXOS = "cisco_nxos"
    ARISTA_EOS = "arista_eos"
    JUNIPER_JUNOS = "juniper_junos"
    FORTINET_FORTIOS = "fortinet_fortios"
    PALO_ALTO_PANOS = "palo_alto_panos"
    CHECKPOINT_GAIA = "checkpoint_gaia"
    GENERIC = "generic"

@dataclass
class VendorProfile:
    """Profile containing vendor-specific configuration patterns and rules."""
    vendor_type: VendorType
    display_name: str
    version_regex: str
    hostname_patterns: List[str]
    command_patterns: Dict[str, str]
    compliance_rules: Dict[str, Dict]
    remediation_templates: Dict[str, List[str]]
    file_extensions: List[str]
    config_sections: Dict[str, str]

class BaseVendorHandler(ABC):
    """Abstract base class for vendor-specific handlers."""
    
    def __init__(self, profile: VendorProfile):
        self.profile = profile
    
    @abstractmethod
    def detect_version(self, config_content: str) -> Optional[str]:
        """Detect the software version from configuration."""
        pass
    
    @abstractmethod
    def extract_hostname(self, config_content: str) -> str:
        """Extract hostname from configuration."""
        pass
    
    @abstractmethod
    def check_aaa_configuration(self, config_content: str) -> Dict:
        """Check AAA configuration compliance."""
        pass
    
    @abstractmethod
    def check_access_control(self, config_content: str) -> Dict:
        """Check access control compliance."""
        pass
    
    @abstractmethod
    def check_boundary_protection(self, config_content: str) -> Dict:
        """Check boundary protection compliance."""
        pass
    
    @abstractmethod
    def generate_remediation(self, failed_checks: Dict) -> List[str]:
        """Generate vendor-specific remediation commands."""
        pass

class CiscoIOSHandler(BaseVendorHandler):
    """Handler for Cisco IOS/IOS-XE platforms."""
    
    def detect_version(self, config_content: str) -> Optional[str]:
        """Detect IOS version."""
        patterns = [
            r'version\s+(\d+\.\d+)',
            r'! IOS\s+Version\s+([^\s,]+)',
            r'Cisco\s+IOS\s+Software.*Version\s+([^\s,]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, config_content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def extract_hostname(self, config_content: str) -> str:
        """Extract hostname from IOS config."""
        match = re.search(r'^hostname\s+(\S+)', config_content, re.MULTILINE | re.IGNORECASE)
        return match.group(1) if match else "Unknown"
    
    def check_aaa_configuration(self, config_content: str) -> Dict:
        """Check AAA configuration for IOS."""
        lines = config_content.lower().split('\n')
        
        # Check for AAA authentication
        aaa_auth = any('aaa authentication login' in line and 'tacacs' in line for line in lines)
        
        # Check for TACACS servers
        tacacs_servers = []
        for line in lines:
            if 'tacacs-server host' in line:
                parts = line.split()
                if len(parts) >= 3:
                    tacacs_servers.append(parts[2])
        
        # Check for local fallback
        local_fallback = any('aaa authentication login' in line and 'local' in line for line in lines)
        
        return {
            'aaa_configured': aaa_auth and local_fallback,
            'tacacs_servers': tacacs_servers,
            'local_fallback': local_fallback,
            'passed': aaa_auth and local_fallback and len(tacacs_servers) > 0
        }
    
    def check_access_control(self, config_content: str) -> Dict:
        """Check access control for IOS."""
        lines = config_content.lower().split('\n')
        
        # Check for enable secret
        enable_secret = any(line.strip().startswith('enable secret') for line in lines)
        
        # Check for SSH-only transport
        ssh_only = False
        in_vty = False
        telnet_found = False
        
        for line in lines:
            line = line.strip()
            if line.startswith('line vty'):
                in_vty = True
                continue
            if in_vty and line.startswith('line '):
                in_vty = False
            if in_vty:
                if 'transport input ssh' in line and 'telnet' not in line:
                    ssh_only = True
                if 'transport input telnet' in line:
                    telnet_found = True
        
        return {
            'enable_secret_present': enable_secret,
            'ssh_only': ssh_only and not telnet_found,
            'no_telnet': not telnet_found,
            'passed': enable_secret and ssh_only and not telnet_found
        }
    
    def check_boundary_protection(self, config_content: str) -> Dict:
        """Check boundary protection for IOS."""
        lines = config_content.lower().split('\n')
        
        # Check for ACLs
        acl_defined = any(line.startswith(('access-list', 'ip access-list')) for line in lines)
        acl_applied = any('ip access-group' in line or 'access-class' in line for line in lines)
        
        # Check for management ACL on VTY
        mgmt_acl = any('access-class' in line for line in lines)
        
        return {
            'acls_present_and_applied': acl_defined and acl_applied,
            'mgmt_acl_signal': mgmt_acl,
            'ssh_mgmt': True,  # Checked in access_control
            'passed': acl_defined and acl_applied and mgmt_acl
        }
    
    def generate_remediation(self, failed_checks: Dict) -> List[str]:
        """Generate IOS-specific remediation commands."""
        commands = []
        
        if not failed_checks.get('aaa_configured', True):
            commands.extend([
                "! Configure AAA authentication",
                "aaa new-model",
                "aaa authentication login default group tacacs+ local",
                "tacacs-server host <TACACS_SERVER_IP> key <SHARED_KEY>",
            ])
        
        if not failed_checks.get('enable_secret_present', True):
            commands.extend([
                "! Configure enable secret",
                "enable secret <STRONG_PASSWORD>",
            ])
        
        if not failed_checks.get('ssh_only', True):
            commands.extend([
                "! Configure SSH-only access",
                "ip domain-name <DOMAIN_NAME>",
                "crypto key generate rsa modulus 2048",
                "line vty 0 15",
                " transport input ssh",
                " no transport input telnet",
            ])
        
        if not failed_checks.get('mgmt_acl_signal', True):
            commands.extend([
                "! Configure management ACL",
                "ip access-list extended MGMT-ACL",
                " permit tcp <MGMT_NETWORK> <WILDCARD> any eq 22",
                " deny ip any any",
                "line vty 0 15",
                " access-class MGMT-ACL in",
            ])
        
        return commands

class AristaEOSHandler(BaseVendorHandler):
    """Handler for Arista EOS platforms."""
    
    def detect_version(self, config_content: str) -> Optional[str]:
        """Detect EOS version."""
        patterns = [
            r'! EOS\s+([^\s,]+)',
            r'Software\s+image\s+version:\s+([^\s,]+)',
            r'Arista\s+.*\s+([0-9]+\.[0-9]+\.[0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, config_content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def extract_hostname(self, config_content: str) -> str:
        """Extract hostname from EOS config."""
        match = re.search(r'^hostname\s+(\S+)', config_content, re.MULTILINE | re.IGNORECASE)
        return match.group(1) if match else "Unknown"
    
    def check_aaa_configuration(self, config_content: str) -> Dict:
        """Check AAA configuration for EOS."""
        lines = config_content.lower().split('\n')
        
        # Similar to IOS but with EOS-specific syntax
        aaa_auth = any('aaa authentication login' in line and 'tacacs' in line for line in lines)
        local_fallback = any('aaa authentication login' in line and 'local' in line for line in lines)
        
        tacacs_servers = []
        for line in lines:
            if 'tacacs-server host' in line:
                parts = line.split()
                if len(parts) >= 3:
                    tacacs_servers.append(parts[2])
        
        return {
            'aaa_configured': aaa_auth and local_fallback,
            'tacacs_servers': tacacs_servers,
            'local_fallback': local_fallback,
            'passed': aaa_auth and local_fallback and len(tacacs_servers) > 0
        }
    
    def check_access_control(self, config_content: str) -> Dict:
        """Check access control for EOS."""
        lines = config_content.lower().split('\n')
        
        # EOS uses similar commands but different management interface
        enable_secret = any(line.strip().startswith('enable secret') for line in lines)
        management_ssh = any('management ssh' in line for line in lines)
        
        return {
            'enable_secret_present': enable_secret,
            'management_ssh': management_ssh,
            'passed': enable_secret and management_ssh
        }
    
    def check_boundary_protection(self, config_content: str) -> Dict:
        """Check boundary protection for EOS."""
        lines = config_content.lower().split('\n')
        
        # Check for Management1 interface with ACL
        mgmt1_present = any('interface management1' in line for line in lines)
        mgmt_acl = False
        
        in_mgmt1 = False
        for line in lines:
            line = line.strip()
            if line.startswith('interface management1'):
                in_mgmt1 = True
                continue
            if in_mgmt1 and line.startswith('interface '):
                in_mgmt1 = False
            if in_mgmt1 and 'ip access-group' in line:
                mgmt_acl = True
        
        acl_defined = any(line.startswith('ip access-list') for line in lines)
        
        return {
            'mgmt_iface_present': mgmt1_present,
            'mgmt_acl_bound': mgmt_acl,
            'acls_present_and_applied': acl_defined and mgmt_acl,
            'passed': mgmt1_present and mgmt_acl and acl_defined
        }
    
    def generate_remediation(self, failed_checks: Dict) -> List[str]:
        """Generate EOS-specific remediation commands."""
        commands = []
        
        if not failed_checks.get('aaa_configured', True):
            commands.extend([
                "! Configure AAA authentication",
                "aaa authentication login default group tacacs+ local",
                "tacacs-server host <TACACS_SERVER_IP> key <SHARED_KEY>",
            ])
        
        if not failed_checks.get('management_ssh', True):
            commands.extend([
                "! Enable management SSH",
                "management ssh",
                "username admin privilege 15 role network-admin secret <PASSWORD>",
            ])
        
        if not failed_checks.get('mgmt_acl_bound', True):
            commands.extend([
                "! Configure Management1 ACL",
                "ip access-list MGMT-ACL",
                " 10 permit tcp <MGMT_NETWORK>/24 any eq ssh",
                " 20 deny ip any any",
                "interface Management1",
                " ip access-group MGMT-ACL in",
            ])
        
        return commands

class CiscoXRHandler(BaseVendorHandler):
    """Handler for Cisco IOS-XR platforms."""
    
    def detect_version(self, config_content: str) -> Optional[str]:
        """Detect IOS-XR version."""
        patterns = [
            r'! IOS XR Configuration ([0-9]+\.[0-9]+\.[0-9]+)',
            r'version\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'Cisco\s+IOS\s+XR\s+Software.*Version\s+([^\s,]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, config_content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def extract_hostname(self, config_content: str) -> str:
        """Extract hostname from XR config."""
        match = re.search(r'^hostname\s+(\S+)', config_content, re.MULTILINE | re.IGNORECASE)
        return match.group(1) if match else "Unknown"
    
    def check_aaa_configuration(self, config_content: str) -> Dict:
        """Check AAA configuration for XR."""
        lines = config_content.lower().split('\n')
        
        # XR has different AAA syntax
        aaa_auth = any('aaa authentication login' in line and 'tacacs' in line for line in lines)
        local_fallback = any('aaa authentication login' in line and 'local' in line for line in lines)
        
        tacacs_servers = []
        for line in lines:
            if 'tacacs-server host' in line or 'tacacs server' in line:
                parts = line.split()
                if len(parts) >= 3:
                    tacacs_servers.append(parts[2])
        
        return {
            'aaa_configured': aaa_auth and local_fallback,
            'tacacs_servers': tacacs_servers,
            'local_fallback': local_fallback,
            'passed': aaa_auth and local_fallback and len(tacacs_servers) > 0
        }
    
    def check_access_control(self, config_content: str) -> Dict:
        """Check access control for XR."""
        lines = config_content.lower().split('\n')
        
        # XR uses different enable secret syntax
        enable_secret = any('enable secret' in line or 'secret' in line for line in lines)
        
        # Check for SSH-only in VTY
        ssh_only = False
        in_vty = False
        
        for line in lines:
            line = line.strip()
            if 'line template vty' in line or 'line console' in line:
                in_vty = True
                continue
            if in_vty and line.startswith(('line ', 'interface ', 'router ')):
                in_vty = False
            if in_vty and 'transport input ssh' in line:
                ssh_only = True
        
        return {
            'enable_secret_present': enable_secret,
            'ssh_only': ssh_only,
            'passed': enable_secret and ssh_only
        }
    
    def check_boundary_protection(self, config_content: str) -> Dict:
        """Check boundary protection for XR."""
        lines = config_content.lower().split('\n')
        
        # Check for ACLs in XR format
        acl_defined = any('ipv4 access-list' in line for line in lines)
        acl_applied = any('ipv4 access-group' in line for line in lines)
        
        return {
            'acls_present_and_applied': acl_defined and acl_applied,
            'mgmt_acl_signal': acl_applied,
            'ssh_mgmt': True,
            'passed': acl_defined and acl_applied
        }
    
    def generate_remediation(self, failed_checks: Dict) -> List[str]:
        """Generate XR-specific remediation commands."""
        commands = []
        
        if not failed_checks.get('aaa_configured', True):
            commands.extend([
                "! Configure AAA authentication for XR",
                "aaa authentication login default group tacacs+ local",
                "tacacs-server host <TACACS_SERVER_IP>",
                " key <SHARED_KEY>",
                "commit",
            ])
        
        if not failed_checks.get('enable_secret_present', True):
            commands.extend([
                "! Configure enable secret for XR",
                "username admin",
                " group root-system",
                " secret <STRONG_PASSWORD>",
                "commit",
            ])
        
        if not failed_checks.get('ssh_only', True):
            commands.extend([
                "! Configure SSH-only access for XR",
                "ssh server v2",
                "line template vty",
                " transport input ssh",
                "commit",
            ])
        
        return commands

class JuniperJunosHandler(BaseVendorHandler):
    """Handler for Juniper Junos platforms."""
    
    def detect_version(self, config_content: str) -> Optional[str]:
        """Detect Junos version."""
        patterns = [
            r'version\s+([0-9]+\.[0-9]+[A-Z0-9.-]*)',
            r'JUNOS\s+([0-9]+\.[0-9]+[A-Z0-9.-]*)',
            r'software-version\s+"([^"]+)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, config_content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def extract_hostname(self, config_content: str) -> str:
        """Extract hostname from Junos config."""
        match = re.search(r'set\s+system\s+host-name\s+(\S+)', config_content, re.IGNORECASE)
        return match.group(1) if match else "Unknown"
    
    def check_aaa_configuration(self, config_content: str) -> Dict:
        """Check AAA configuration for Junos."""
        lines = config_content.lower().split('\n')
        
        # Junos uses different syntax
        tacplus_configured = any('set system tacplus-server' in line for line in lines)
        auth_order = any('set system authentication-order' in line and 'tacplus' in line for line in lines)
        local_fallback = any('set system authentication-order' in line and 'password' in line for line in lines)
        
        tacacs_servers = []
        for line in lines:
            if 'set system tacplus-server' in line:
                parts = line.split()
                if len(parts) >= 3:
                    tacacs_servers.append(parts[2])
        
        return {
            'aaa_configured': tacplus_configured and auth_order and local_fallback,
            'tacacs_servers': tacacs_servers,
            'local_fallback': local_fallback,
            'passed': tacplus_configured and auth_order and local_fallback
        }
    
    def check_access_control(self, config_content: str) -> Dict:
        """Check access control for Junos."""
        lines = config_content.lower().split('\n')
        
        # Check for root authentication
        root_auth = any('set system root-authentication' in line for line in lines)
        
        # Check for SSH-only
        ssh_only = any('set system services ssh' in line for line in lines)
        no_telnet = not any('set system services telnet' in line for line in lines)
        
        return {
            'enable_secret_present': root_auth,
            'ssh_only': ssh_only and no_telnet,
            'no_telnet': no_telnet,
            'passed': root_auth and ssh_only and no_telnet
        }
    
    def check_boundary_protection(self, config_content: str) -> Dict:
        """Check boundary protection for Junos."""
        lines = config_content.lower().split('\n')
        
        # Check for firewall filters
        filter_defined = any('set firewall filter' in line for line in lines)
        filter_applied = any('set interfaces' in line and 'filter' in line for line in lines)
        
        return {
            'acls_present_and_applied': filter_defined and filter_applied,
            'mgmt_acl_signal': filter_applied,
            'ssh_mgmt': True,
            'passed': filter_defined and filter_applied
        }
    
    def generate_remediation(self, failed_checks: Dict) -> List[str]:
        """Generate Junos-specific remediation commands."""
        commands = []
        
        if not failed_checks.get('aaa_configured', True):
            commands.extend([
                "! Configure TACACS+ authentication for Junos",
                "set system tacplus-server <TACACS_SERVER_IP> secret <SHARED_KEY>",
                "set system authentication-order [ tacplus password ]",
                "commit",
            ])
        
        if not failed_checks.get('enable_secret_present', True):
            commands.extend([
                "! Configure root authentication for Junos",
                "set system root-authentication encrypted-password <ENCRYPTED_PASSWORD>",
                "commit",
            ])
        
        if not failed_checks.get('ssh_only', True):
            commands.extend([
                "! Configure SSH-only access for Junos",
                "set system services ssh",
                "delete system services telnet",
                "commit",
            ])
        
        return commands

class VendorManager:
    """Central manager for vendor detection and handling."""
    
    def __init__(self):
        self.handlers = {
            VendorType.CISCO_IOS: CiscoIOSHandler,
            VendorType.CISCO_XE: CiscoIOSHandler,  # Same handler for now
            VendorType.CISCO_XR: CiscoXRHandler,
            VendorType.ARISTA_EOS: AristaEOSHandler,
            VendorType.JUNIPER_JUNOS: JuniperJunosHandler,
        }
        self.profiles = self._load_vendor_profiles()
    
    def _load_vendor_profiles(self) -> Dict[VendorType, VendorProfile]:
        """Load vendor profiles from configuration."""
        profiles = {}
        
        # Cisco IOS/XE Profile
        cisco_ios_profile = VendorProfile(
            vendor_type=VendorType.CISCO_IOS,
            display_name="Cisco IOS/IOS-XE",
            version_regex=r'version\s+(\d+\.\d+)',
            hostname_patterns=[r'^hostname\s+(\S+)'],
            command_patterns={
                'show_version': 'show version',
                'show_running': 'show running-config',
                'show_interfaces': 'show ip interface brief'
            },
            compliance_rules={
                'aaa_required': True,
                'ssh_only': True,
                'enable_secret': True
            },
            remediation_templates={
                'aaa_config': [
                    'aaa new-model',
                    'aaa authentication login default group tacacs+ local'
                ],
                'ssh_config': [
                    'ip domain-name {domain}',
                    'crypto key generate rsa modulus 2048',
                    'line vty 0 15',
                    ' transport input ssh'
                ]
            },
            file_extensions=['.cfg', '.conf', '.txt'],
            config_sections={
                'interfaces': r'^interface\s+',
                'routing': r'^router\s+',
                'acl': r'^(ip\s+)?access-list\s+'
            }
        )
        profiles[VendorType.CISCO_IOS] = cisco_ios_profile
        profiles[VendorType.CISCO_XE] = cisco_ios_profile
        
        # Cisco XR Profile
        cisco_xr_profile = VendorProfile(
            vendor_type=VendorType.CISCO_XR,
            display_name="Cisco IOS-XR",
            version_regex=r'! IOS XR Configuration ([0-9]+\.[0-9]+\.[0-9]+)',
            hostname_patterns=[r'^hostname\s+(\S+)'],
            command_patterns={
                'show_version': 'show version',
                'show_running': 'show running-config',
                'show_interfaces': 'show interfaces brief'
            },
            compliance_rules={
                'aaa_required': True,
                'ssh_only': True,
                'user_auth': True
            },
            remediation_templates={
                'aaa_config': [
                    'aaa authentication login default group tacacs+ local',
                    'commit'
                ],
                'ssh_config': [
                    'ssh server v2',
                    'line template vty',
                    ' transport input ssh',
                    'commit'
                ]
            },
            file_extensions=['.cfg', '.conf', '.xr'],
            config_sections={
                'interfaces': r'^interface\s+',
                'routing': r'^router\s+',
                'acl': r'^ipv4\s+access-list\s+'
            }
        )
        profiles[VendorType.CISCO_XR] = cisco_xr_profile
        
        # Arista EOS Profile
        arista_profile = VendorProfile(
            vendor_type=VendorType.ARISTA_EOS,
            display_name="Arista EOS",
            version_regex=r'! Software\s+image\s+version:\s+([^\s,]+)',
            hostname_patterns=[r'^hostname\s+(\S+)'],
            command_patterns={
                'show_version': 'show version',
                'show_running': 'show running-config',
                'show_interfaces': 'show interfaces status'
            },
            compliance_rules={
                'management_ssh': True,
                'mgmt_interface': True
            },
            remediation_templates={
                'management_ssh': ['management ssh'],
                'mgmt_acl': [
                    'ip access-list MGMT-ACL',
                    ' 10 permit tcp {mgmt_network} any eq ssh',
                    'interface Management1',
                    ' ip access-group MGMT-ACL in'
                ]
            },
            file_extensions=['.cfg', '.conf', '.eos'],
            config_sections={
                'interfaces': r'^interface\s+',
                'routing': r'^router\s+',
                'acl': r'^ip\s+access-list\s+'
            }
        )
        profiles[VendorType.ARISTA_EOS] = arista_profile
        
        # Juniper Junos Profile
        juniper_profile = VendorProfile(
            vendor_type=VendorType.JUNIPER_JUNOS,
            display_name="Juniper Junos",
            version_regex=r'version\s+([0-9]+\.[0-9]+[A-Z0-9.-]*)',
            hostname_patterns=[r'set\s+system\s+host-name\s+(\S+)'],
            command_patterns={
                'show_version': 'show version',
                'show_config': 'show configuration',
                'show_interfaces': 'show interfaces terse'
            },
            compliance_rules={
                'tacplus_required': True,
                'ssh_only': True,
                'root_auth': True
            },
            remediation_templates={
                'tacplus_config': [
                    'set system tacplus-server {server} secret {key}',
                    'set system authentication-order [ tacplus password ]',
                    'commit'
                ],
                'ssh_config': [
                    'set system services ssh',
                    'delete system services telnet',
                    'commit'
                ]
            },
            file_extensions=['.cfg', '.conf', '.junos'],
            config_sections={
                'interfaces': r'set\s+interfaces\s+',
                'routing': r'set\s+protocols\s+',
                'firewall': r'set\s+firewall\s+'
            }
        )
        profiles[VendorType.JUNIPER_JUNOS] = juniper_profile
        
        return profiles
    
    def detect_vendor(self, config_content: str, filename: str = "") -> Tuple[VendorType, Optional[str]]:
        """Auto-detect vendor and version from configuration content."""
        
        # Detection patterns for each vendor
        detection_patterns = {
            VendorType.CISCO_IOS: [
                r'Cisco\s+IOS\s+Software',
                r'version\s+\d+\.\d+',
                r'hostname\s+\S+.*\n.*line\s+con',
                r'ip\s+access-list\s+extended'
            ],
            VendorType.CISCO_XE: [
                r'Cisco\s+IOS\s+XE\s+Software',
                r'IOS-XE',
                r'version\s+1[56789]\.\d+'  # XE versions typically 15+
            ],
            VendorType.CISCO_XR: [
                r'IOS\s+XR\s+Configuration',
                r'Cisco\s+IOS\s+XR',
                r'ipv4\s+access-list',
                r'commit'
            ],
            VendorType.ARISTA_EOS: [
                r'! EOS',
                r'management\s+ssh',
                r'interface\s+Management1',
                r'username\s+\S+\s+role'
            ],
            VendorType.JUNIPER_JUNOS: [
                r'set\s+system\s+host-name',
                r'JUNOS',
                r'set\s+interfaces\s+',
                r'set\s+firewall\s+filter'
            ]
        }
        
        # Score each vendor type
        vendor_scores = {}
        for vendor_type, patterns in detection_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, config_content, re.IGNORECASE | re.MULTILINE):
                    score += 1
            vendor_scores[vendor_type] = score
        
        # Get highest scoring vendor
        if vendor_scores:
            detected_vendor = max(vendor_scores, key=vendor_scores.get)
            if vendor_scores[detected_vendor] > 0:
                # Try to detect version
                if detected_vendor in self.handlers:
                    handler_class = self.handlers[detected_vendor]
                    profile = self.profiles[detected_vendor]
                    handler = handler_class(profile)
                    version = handler.detect_version(config_content)
                    return detected_vendor, version
        
        return VendorType.GENERIC, None
    
    def get_handler(self, vendor_type: VendorType) -> Optional[BaseVendorHandler]:
        """Get appropriate handler for vendor type."""
        if vendor_type in self.handlers:
            handler_class = self.handlers[vendor_type]
            profile = self.profiles[vendor_type]
            return handler_class(profile)
        return None
    
    def get_supported_vendors(self) -> List[Dict]:
        """Get list of supported vendors for UI display."""
        vendors = []
        for vendor_type, profile in self.profiles.items():
            vendors.append({
                'type': vendor_type.value,
                'display_name': profile.display_name,
                'extensions': profile.file_extensions
            })
        return vendors
    
    def check_compliance_multi_vendor(self, config_content: str, vendor_type: VendorType = None) -> Dict:
        """Run compliance check with vendor-specific logic."""
        
        # Auto-detect if not specified
        if vendor_type is None:
            vendor_type, version = self.detect_vendor(config_content)
        else:
            handler = self.get_handler(vendor_type)
            version = handler.detect_version(config_content) if handler else None
        
        # Get appropriate handler
        handler = self.get_handler(vendor_type)
        if not handler:
            # Fall back to generic handler
            return self._generic_compliance_check(config_content)
        
        # Run vendor-specific checks
        try:
            hostname = handler.extract_hostname(config_content)
            aaa_result = handler.check_aaa_configuration(config_content)
            access_result = handler.check_access_control(config_content)
            boundary_result = handler.check_boundary_protection(config_content)
            
            # Calculate overall compliance
            all_passed = (
                aaa_result.get('passed', False) and
                access_result.get('passed', False) and
                boundary_result.get('passed', False)
            )
            
            return {
                'hostname': hostname,
                'vendor_type': vendor_type.value,
                'vendor_display': self.profiles[vendor_type].display_name,
                'detected_version': version,
                'compliant': all_passed,
                'checks': {
                    'AC.L1-3.1.1': aaa_result,
                    'AC.L1-3.1.2': access_result,
                    'SC.L1-3.13.1': boundary_result
                }
            }
            
        except Exception as e:
            return {
                'hostname': 'Unknown',
                'vendor_type': vendor_type.value,
                'error': str(e),
                'compliant': False,
                'checks': {}
            }
    
    def _generic_compliance_check(self, config_content: str) -> Dict:
        """Generic compliance check for unsupported vendors."""
        return {
            'hostname': 'Unknown',
            'vendor_type': 'generic',
            'vendor_display': 'Generic/Unsupported',
            'detected_version': None,
            'compliant': False,
            'checks': {},
            'warning': 'Vendor not supported - using generic checks'
        }
    
    def generate_vendor_remediation(self, vendor_type: VendorType, failed_checks: Dict) -> List[str]:
        """Generate vendor-specific remediation commands."""
        handler = self.get_handler(vendor_type)
        if handler:
            return handler.generate_remediation(failed_checks)
        return []

# Enhanced GUI integration
class VendorSelectionWidget:
    """Widget for vendor selection in GUI."""
    
    def __init__(self, parent, vendor_manager: VendorManager):
        self.parent = parent
        self.vendor_manager = vendor_manager
        self.vendor_var = None
        self.create_widget()
    
    def create_widget(self):
        """Create vendor selection widget."""
        import tkinter as tk
        from tkinter import ttk
        
        # Vendor selection frame
        vendor_frame = ttk.LabelFrame(self.parent, text="Vendor/Platform Selection", padding="10")
        vendor_frame.pack(fill="x", pady=(0, 10))
        
        # Auto-detect option
        self.vendor_var = tk.StringVar(value="auto")
        ttk.Radiobutton(vendor_frame, text="Auto-detect vendor", 
                       variable=self.vendor_var, value="auto").pack(anchor="w")
        
        # Manual vendor selection
        ttk.Label(vendor_frame, text="Or select manually:").pack(anchor="w", pady=(10, 5))
        
        vendor_combo_frame = ttk.Frame(vendor_frame)
        vendor_combo_frame.pack(fill="x")
        
        self.vendor_combo = ttk.Combobox(vendor_combo_frame, state="readonly", width=30)
        self.vendor_combo.pack(side="left", padx=(20, 10))
        
        # Populate vendor list
        vendors = self.vendor_manager.get_supported_vendors()
        vendor_options = [f"{v['display_name']}" for v in vendors]
        self.vendor_combo['values'] = vendor_options
        
        # Vendor selection radio button
        ttk.Radiobutton(vendor_combo_frame, text="Use selected vendor", 
                       variable=self.vendor_var, value="manual").pack(side="left")
        
        # Version detection display
        self.version_label = ttk.Label(vendor_frame, text="Version: Not detected", 
                                      foreground="gray")
        self.version_label.pack(anchor="w", pady=(5, 0))
    
    def get_selected_vendor(self) -> Optional[VendorType]:
        """Get currently selected vendor type."""
        if self.vendor_var.get() == "auto":
            return None  # Auto-detect
        
        selected_idx = self.vendor_combo.current()
        if selected_idx >= 0:
            vendors = self.vendor_manager.get_supported_vendors()
            vendor_type_str = vendors[selected_idx]['type']
            return VendorType(vendor_type_str)
        
        return None
    
    def update_version_display(self, version: str, vendor_name: str):
        """Update version display."""
        if version:
            self.version_label.config(text=f"Detected: {vendor_name} {version}", 
                                     foreground="green")
        else:
            self.version_label.config(text="Version: Not detected", 
                                     foreground="gray")

# Testing and validation functions
def test_vendor_detection():
    """Test vendor detection with sample configurations."""
    manager = VendorManager()
    
    test_configs = {
        "Cisco IOS": """
        version 15.7
        hostname CiscoRouter01
        !
        aaa new-model
        aaa authentication login default group tacacs+ local
        tacacs-server host 192.168.1.100 key secretkey
        !
        enable secret 5 $1$hash$example
        !
        line vty 0 4
         transport input ssh
         access-class MGMT-ACL in
        """,
        
        "Cisco XR": """
        !! IOS XR Configuration 7.3.1
        hostname XRRouter01
        !
        aaa authentication login default group tacacs+ local
        tacacs-server host 192.168.1.100
         key secretkey
        !
        username admin
         group root-system
         secret password123
        !
        ssh server v2
        line template vty
         transport input ssh
        !
        commit
        """,
        
        "Arista EOS": """
        ! EOS 4.28.1F
        hostname AristaSwitch01
        !
        management ssh
        !
        aaa authentication login default group tacacs+ local
        tacacs-server host 192.168.1.100 key secretkey
        !
        username admin role network-admin secret password123
        !
        interface Management1
         ip address 192.168.1.10/24
         ip access-group MGMT-ACL in
        !
        ip access-list MGMT-ACL
         10 permit tcp 192.168.1.0/24 any eq ssh
         20 deny ip any any
        """,
        
        "Juniper Junos": """
        version 20.4R3.8;
        system {
            host-name JuniperRouter01;
            root-authentication {
                encrypted-password "$6$hash$example";
            }
            authentication-order [ tacplus password ];
            tacplus-server {
                192.168.1.100 {
                    secret "secretkey";
                }
            }
            services {
                ssh;
            }
        }
        firewall {
            filter MGMT-ACL {
                term allow-ssh {
                    from {
                        source-address {
                            192.168.1.0/24;
                        }
                        protocol tcp;
                        destination-port ssh;
                    }
                    then accept;
                }
                term deny-all {
                    then discard;
                }
            }
        }
        """
    }
    
    print("🔍 Testing Vendor Detection")
    print("=" * 50)
    
    for vendor_name, config in test_configs.items():
        vendor_type, version = manager.detect_vendor(config)
        print(f"\n📋 {vendor_name}:")
        print(f"   Detected: {vendor_type.value}")
        print(f"   Version: {version or 'Not detected'}")
        
        # Run compliance check
        result = manager.check_compliance_multi_vendor(config)
        print(f"   Hostname: {result['hostname']}")
        print(f"   Compliant: {result['compliant']}")
        
        # Show specific check results
        for control, data in result.get('checks', {}).items():
            status = "✅ PASS" if data.get('passed') else "❌ FAIL"
            print(f"   {control}: {status}")

def validate_remediation_commands():
    """Validate remediation command generation."""
    manager = VendorManager()
    
    # Test failed checks for each vendor
    failed_checks = {
        'aaa_configured': False,
        'enable_secret_present': False,
        'ssh_only': False,
        'mgmt_acl_signal': False
    }
    
    print("\n🔧 Testing Remediation Generation")
    print("=" * 50)
    
    for vendor_type in [VendorType.CISCO_IOS, VendorType.CISCO_XR, 
                        VendorType.ARISTA_EOS, VendorType.JUNIPER_JUNOS]:
        handler = manager.get_handler(vendor_type)
        if handler:
            commands = handler.generate_remediation(failed_checks)
            print(f"\n📝 {vendor_type.value} Remediation:")
            for cmd in commands[:5]:  # Show first 5 commands
                print(f"   {cmd}")
            if len(commands) > 5:
                print(f"   ... and {len(commands) - 5} more commands")

# Main execution
if __name__ == "__main__":
    # Run tests
    test_vendor_detection()
    validate_remediation_commands()
    
    print("\n🎉 Multi-vendor system test complete!")
    print("💡 Integration ready for GUI and API frameworks!")