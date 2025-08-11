# enhanced_features/config_validator.py
"""Advanced configuration validation and recommendations."""

class CMMCConfigValidator:
    def __init__(self):
        self.validation_rules = self._load_validation_rules()
        self.remediation_templates = self._load_remediation_templates()
    
    def validate_configuration(self, config_path, device_type="auto"):
        """Perform comprehensive configuration validation."""
        with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
            config_lines = f.readlines()
        
        # Auto-detect device type if not specified
        if device_type == "auto":
            device_type = self._detect_device_type(config_lines)
        
        validation_results = {
            'device_type': device_type,
            'security_score': 0,
            'vulnerabilities': [],
            'recommendations': [],
            'remediation_commands': []
        }
        
        # Run validation checks
        validation_results.update(self._run_security_checks(config_lines, device_type))
        
        return validation_results
    
    def _detect_device_type(self, config_lines):
        """Auto-detect device type from configuration."""
        config_text = ''.join(config_lines).lower()
        
        if 'management ssh' in config_text and 'switchport' in config_text:
            return 'arista_switch'
        elif 'switchport' in config_text:
            return 'cisco_switch'
        elif 'router ospf' in config_text or 'router bgp' in config_text:
            return 'cisco_router'
        else:
            return 'unknown'
    
    def _run_security_checks(self, config_lines, device_type):
        """Run comprehensive security validation checks."""
        results = {
            'security_score': 0,
            'vulnerabilities': [],
            'recommendations': [],
            'remediation_commands': []
        }
        
        config_text = ''.join(config_lines).lower()
        
        # Check for common security vulnerabilities
        checks = [
            self._check_weak_passwords(config_lines),
            self._check_unnecessary_services(config_lines),
            self._check_logging_configuration(config_lines),
            self._check_snmp_security(config_lines),
            self._check_ntp_configuration(config_lines),
            self._check_interface_security(config_lines),
            self._check_routing_security(config_lines, device_type)
        ]
        
        # Aggregate results
        total_score = 0
        for check_result in checks:
            total_score += check_result['score']
            results['vulnerabilities'].extend(check_result['vulnerabilities'])
            results['recommendations'].extend(check_result['recommendations'])
            results['remediation_commands'].extend(check_result['remediation_commands'])
        
        results['security_score'] = min(100, total_score // len(checks))
        
        return results
    
    def _check_weak_passwords(self, config_lines):
        """Check for weak password configurations."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        for line in config_lines:
            line_lower = line.lower().strip()
            
            # Check for plaintext passwords
            if 'password ' in line_lower and 'secret' not in line_lower:
                result['vulnerabilities'].append("Plaintext password detected")
                result['recommendations'].append("Use 'secret' instead of 'password' for encrypted storage")
                result['remediation_commands'].append("Replace 'password' with 'secret' commands")
                result['score'] -= 20
            
            # Check for default passwords
            default_passwords = ['cisco', 'admin', 'password', '123456']
            for pwd in default_passwords:
                if f'password {pwd}' in line_lower or f'secret {pwd}' in line_lower:
                    result['vulnerabilities'].append(f"Default password '{pwd}' detected")
                    result['recommendations'].append("Change default passwords to strong, unique passwords")
                    result['remediation_commands'].append(f"Change password from default '{pwd}'")
                    result['score'] -= 30
        
        return result
    
    def _check_unnecessary_services(self, config_lines):
        """Check for unnecessary or insecure services."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        config_text = ''.join(config_lines).lower()
        
        # Check for insecure services
        insecure_services = {
            'ip http server': ('HTTP server enabled', 'Disable HTTP server', 'no ip http server'),
            'service finger': ('Finger service enabled', 'Disable finger service', 'no service finger'),
            'ip bootp server': ('BOOTP server enabled', 'Disable BOOTP server', 'no ip bootp server'),
            'service tcp-small-servers': ('TCP small servers enabled', 'Disable TCP small servers', 'no service tcp-small-servers'),
            'service udp-small-servers': ('UDP small servers enabled', 'Disable UDP small servers', 'no service udp-small-servers')
        }
        
        for service, (vuln, rec, cmd) in insecure_services.items():
            if service in config_text:
                result['vulnerabilities'].append(vuln)
                result['recommendations'].append(rec)
                result['remediation_commands'].append(cmd)
                result['score'] -= 15
        
        return result
    
    def _check_logging_configuration(self, config_lines):
        """Check logging configuration."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        config_text = ''.join(config_lines).lower()
        
        # Check for logging configuration
        if 'logging' not in config_text:
            result['vulnerabilities'].append("No logging configuration found")
            result['recommendations'].append("Configure centralized logging")
            result['remediation_commands'].append("logging host <syslog-server>")
            result['score'] -= 25
        
        # Check for buffer size
        if 'logging buffered' not in config_text:
            result['recommendations'].append("Configure logging buffer for local log storage")
            result['remediation_commands'].append("logging buffered 32768")
        
        # Check for timestamp configuration
        if 'service timestamps' not in config_text:
            result['recommendations'].append("Enable timestamps on log messages")
            result['remediation_commands'].append("service timestamps log datetime msec localtime")
        
        return result
    
    def _check_snmp_security(self, config_lines):
        """Check SNMP security configuration."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        config_text = ''.join(config_lines).lower()
        
        # Check for SNMPv1/v2c
        if 'snmp-server community' in config_text:
            result['vulnerabilities'].append("SNMPv1/v2c community strings detected")
            result['recommendations'].append("Migrate to SNMPv3 with authentication and encryption")
            result['remediation_commands'].append("Configure SNMPv3 user with auth and priv")
            result['score'] -= 20
        
        # Check for default community strings
        default_communities = ['public', 'private']
        for community in default_communities:
            if f'community {community}' in config_text:
                result['vulnerabilities'].append(f"Default SNMP community '{community}' detected")
                result['recommendations'].append("Remove default SNMP community strings")
                result['remediation_commands'].append(f"no snmp-server community {community}")
                result['score'] -= 30
        
        return result
    
    def _check_ntp_configuration(self, config_lines):
        """Check NTP configuration."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        config_text = ''.join(config_lines).lower()
        
        if 'ntp server' not in config_text and 'ntp peer' not in config_text:
            result['recommendations'].append("Configure NTP for accurate time synchronization")
            result['remediation_commands'].append("ntp server <ntp-server-ip>")
        
        # Check for NTP authentication
        if 'ntp server' in config_text and 'ntp authenticate' not in config_text:
            result['recommendations'].append("Enable NTP authentication")
            result['remediation_commands'].append("ntp authenticate")
            result['remediation_commands'].append("ntp authentication-key 1 md5 <key>")
        
        return result
    
    def _check_interface_security(self, config_lines):
        """Check interface security configurations."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        # Check for unused interfaces
        in_interface = False
        interface_name = ""
        
        for line in config_lines:
            line_strip = line.strip()
            line_lower = line_strip.lower()
            
            if line_lower.startswith('interface '):
                in_interface = True
                interface_name = line_strip
                interface_has_shutdown = False
                interface_has_description = False
                continue
            
            if in_interface and line_lower.startswith(('interface ', 'line ', 'router ', '!')):
                # End of interface block
                if not interface_has_shutdown and not interface_has_description:
                    result['recommendations'].append(f"Add description to {interface_name}")
                    result['remediation_commands'].append(f"interface {interface_name.split()[1]}")
                    result['remediation_commands'].append(" description <interface description>")
                in_interface = False
                continue
            
            if in_interface:
                if 'shutdown' in line_lower:
                    interface_has_shutdown = True
                if 'description' in line_lower:
                    interface_has_description = True
        
        return result
    
    def _check_routing_security(self, config_lines, device_type):
        """Check routing protocol security."""
        result = {'score': 100, 'vulnerabilities': [], 'recommendations': [], 'remediation_commands': []}
        
        if device_type not in ['cisco_router', 'arista_router']:
            return result
        
        config_text = ''.join(config_lines).lower()
        
        # Check for routing protocol authentication
        if 'router ospf' in config_text and 'area' in config_text:
            if 'authentication' not in config_text:
                result['recommendations'].append("Enable OSPF authentication")
                result['remediation_commands'].append("router ospf 1")
                result['remediation_commands'].append(" area 0 authentication message-digest")
        
        if 'router bgp' in config_text:
            if 'password' not in config_text:
                result['recommendations'].append("Configure BGP neighbor authentication")
                result['remediation_commands'].append("router bgp <asn>")
                result['remediation_commands'].append(" neighbor <ip> password <password>")
        
        return result
    
    def _load_validation_rules(self):
        """Load validation rules (in real implementation, this could be from a file)."""
        return {
            'password_complexity': {
                'min_length': 8,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special': True
            },
            'allowed_services': [
                'ssh', 'ntp', 'dns', 'dhcp'
            ],
            'required_configs': [
                'enable secret',
                'aaa authentication',
                'logging',
                'ntp server'
            ]
        }
    
    def _load_remediation_templates(self):
        """Load remediation command templates."""
        return {
            'cisco': {
                'secure_vty': [
                    'line vty 0 15',
                    ' transport input ssh',
                    ' access-class <acl-name> in',
                    ' exec-timeout 5 0',
                    ' logging synchronous'
                ],
                'secure_console': [
                    'line con 0',
                    ' exec-timeout 5 0',
                    ' logging synchronous'
                ],
                'basic_hardening': [
                    'no ip http server',
                    'no ip http secure-server',
                    'service password-encryption',
                    'service timestamps debug datetime msec',
                    'service timestamps log datetime msec'
                ]
            },
            'arista': {
                'secure_management': [
                    'management ssh',
                    'management api http-commands',
                    ' no shutdown',
                    ' protocol https'
                ],
                'basic_hardening': [
                    'ip routing',
                    'service routing protocols model multi-agent'
                ]
            }
        }