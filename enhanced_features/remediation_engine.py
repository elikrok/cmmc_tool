# enhanced_features/remediation_engine.py
"""Automated remediation command generation."""

class CMMCRemediationEngine:
    def __init__(self):
        self.remediation_templates = self._load_templates()
    
    def generate_remediation_plan(self, compliance_results):
        """Generate comprehensive remediation plan."""
        plan = {
            'device_plans': [],
            'summary': {
                'total_devices': len(compliance_results),
                'devices_needing_remediation': 0,
                'total_commands': 0,
                'estimated_time_minutes': 0
            }
        }
        
        for result in compliance_results:
            device_plan = self._generate_device_plan(result)
            if device_plan['commands']:
                plan['device_plans'].append(device_plan)
                plan['summary']['devices_needing_remediation'] += 1
                plan['summary']['total_commands'] += len(device_plan['commands'])
                plan['summary']['estimated_time_minutes'] += device_plan['estimated_minutes']
        
        return plan
    
    def _generate_device_plan(self, result):
        """Generate remediation plan for a single device."""
        hostname = result.get('hostname', 'Unknown')
        checks = result.get('checks', {})
        
        device_plan = {
            'hostname': hostname,
            'commands': [],
            'priorities': [],
            'estimated_minutes': 0,
            'backup_required': True,
            'reboot_required': False
        }
        
        # Analyze each failed control
        for control, data in checks.items():
            if not data.get('passed', True):
                commands = self._get_control_remediation(control, data, result)
                device_plan['commands'].extend(commands)
        
        # Estimate time and set priorities
        device_plan['estimated_minutes'] = len(device_plan['commands']) * 2  # 2 minutes per command
        device_plan['priorities'] = self._prioritize_commands(device_plan['commands'])
        
        return device_plan
    
    def _get_control_remediation(self, control, data, result):
        """Get remediation commands for specific control failure."""
        commands = []
        
        if control == 'AC.L1-3.1.1':
            # AAA authentication issues
            if not data.get('aaa_configured'):
                commands.extend([
                    "! Configure AAA authentication",
                    "aaa authentication login default group tacacs+ local",
                    "aaa group server tacacs+ TACACS-GROUP",
                    " server 192.168.1.100",
                    " server 192.168.1.101",
                    "tacacs-server host 192.168.1.100 key <your-key>",
                    "tacacs-server host 192.168.1.101 key <your-key>"
                ])
            
            if not data.get('tacacs_servers'):
                commands.extend([
                    "! Add TACACS+ servers",
                    "tacacs-server host <tacacs-server-ip> key <shared-key>"
                ])
        
        elif control == 'AC.L1-3.1.2':
            # Access control issues
            if not data.get('enable_secret_present'):
                commands.extend([
                    "! Configure enable secret",
                    "enable secret <strong-password>"
                ])
            
            if not data.get('no_telnet'):
                commands.extend([
                    "! Disable Telnet, enable SSH only",
                    "line vty 0 15",
                    " transport input ssh",
                    " no transport input telnet"
                ])
            
            # Add user privilege configurations
            user_privs = data.get('user_privileges', {})
            if not user_privs:
                commands.extend([
                    "! Configure user accounts with appropriate privileges",
                    "username admin privilege 15 secret <admin-password>",
                    "username operator privilege 5 secret <operator-password>"
                ])
        
        elif control == 'SC.L1-3.13.1':
            # Boundary protection issues
            if not data.get('ssh_mgmt'):
                commands.extend([
                    "! Configure SSH management",
                    "ip domain-name yourdomain.com",
                    "crypto key generate rsa modulus 2048",
                    "line vty 0 15",
                    " transport input ssh"
                ])
            
            if not data.get('acls_present_and_applied'):
                commands.extend([
                    "! Configure management ACL",
                    "ip access-list extended MGMT-ACL",
                    " permit tcp 192.168.100.0 0.0.0.255 any eq 22",
                    " deny ip any any",
                    "line vty 0 15",
                    " access-class MGMT-ACL in"
                ])
            
            if not data.get('mgmt_vrf_or_mgmt1'):
                commands.extend([
                    "! Consider implementing management VRF",
                    "! ip vrf MGMT",
                    "! interface <mgmt-interface>",
                    "!  ip vrf forwarding MGMT"
                ])
        
        elif control == 'SC.L1-3.13.5':
            # DMZ separation issues
            dmz_interfaces = data.get('dmz_interfaces_without_acl', [])
            if dmz_interfaces:
                commands.extend([
                    "! Configure DMZ access control",
                    "ip access-list extended DMZ-ACL",
                    " permit tcp any host <dmz-server-ip> eq 80",
                    " permit tcp any host <dmz-server-ip> eq 443", 
                    " deny ip any any"
                ])
                
                for interface in dmz_interfaces[:3]:  # Show first 3
                    if_name = interface.replace('interface ', '').replace('Interface ', '')
                    commands.extend([
                        f"interface {if_name}",
                        " ip access-group DMZ-ACL in"
                    ])
        
        return commands
    
    def _prioritize_commands(self, commands):
        """Assign priorities to commands based on security impact."""
        priorities = []
        
        for cmd in commands:
            if any(keyword in cmd.lower() for keyword in ['enable secret', 'aaa authentication']):
                priorities.append('HIGH')
            elif any(keyword in cmd.lower() for keyword in ['transport input ssh', 'access-class']):
                priorities.append('MEDIUM')
            else:
                priorities.append('LOW')
        
        return priorities
    
    def export_remediation_scripts(self, plan, output_dir):
        """Export remediation commands as executable scripts."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate master script
        master_script = output_path / "master_remediation.txt"
        with open(master_script, 'w') as f:
            f.write("CMMC 2.0 Level 1 Remediation Plan\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total Devices: {plan['summary']['total_devices']}\n")
            f.write(f"Devices Needing Remediation: {plan['summary']['devices_needing_remediation']}\n")
            f.write(f"Total Commands: {plan['summary']['total_commands']}\n")
            f.write(f"Estimated Time: {plan['summary']['estimated_time_minutes']} minutes\n\n")
            
            f.write("IMPORTANT NOTES:\n")
            f.write("- Always backup configurations before applying changes\n")
            f.write("- Test changes in a lab environment first\n")
            f.write("- Apply changes during maintenance windows\n")
            f.write("- Verify connectivity after each major change\n\n")
        
        # Generate individual device scripts
        for device_plan in plan['device_plans']:
            device_script = output_path / f"{device_plan['hostname']}_remediation.txt"
            with open(device_script, 'w') as f:
                f.write(f"Remediation Commands for {device_plan['hostname']}\n")
                f.write("=" * 50 + "\n\n")
                f.write("BACKUP CONFIGURATION FIRST:\n")
                f.write("copy running-config startup-config\n")
                f.write("copy running-config tftp://backup-server/config-backup.txt\n\n")
                f.write("REMEDIATION COMMANDS:\n")
                f.write("-" * 30 + "\n")
                
                for i, cmd in enumerate(device_plan['commands']):
                    priority = device_plan['priorities'][i] if i < len(device_plan['priorities']) else 'LOW'
                    if cmd.startswith('!'):
                        f.write(f"\n{cmd}\n")
                    else:
                        f.write(f"{cmd}  ! Priority: {priority}\n")
                
                f.write("\nSAVE CONFIGURATION:\n")
                f.write("copy running-config startup-config\n")
                f.write("\nVERIFY CHANGES:\n")
                f.write("show running-config | include aaa\n")
                f.write("show running-config | include tacacs\n")
                f.write("show running-config | include access-list\n")
        
        return str(master_script)
    
    def _load_templates(self):
        """Load remediation command templates."""
        return {
            'cisco_basic_hardening': [
                'no ip http server',
                'no ip http secure-server', 
                'service password-encryption',
                'service timestamps debug datetime msec localtime',
                'service timestamps log datetime msec localtime',
                'no ip source-route',
                'no ip finger',
                'no service finger',
                'no cdp run'
            ],
            'arista_basic_hardening': [
                'management ssh',
                'management api http-commands',
                ' no shutdown',
                ' protocol https'
            ]
        }