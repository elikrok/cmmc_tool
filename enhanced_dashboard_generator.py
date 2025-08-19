# enhanced_dashboard_generator.py
"""Enhanced HTML dashboard generator that dynamically creates content from compliance results."""

import json
from datetime import datetime
from pathlib import Path

class EnhancedCMMCDashboard:
    def __init__(self):
        self.cmmc_controls = self._load_comprehensive_cmmc_definitions()
        
    def _load_comprehensive_cmmc_definitions(self):
        """Load comprehensive CMMC control definitions with detailed explanations."""
        return {
            'CM.L1-3.4.1': {
                'title': 'CM.L1-3.4.1 - Configuration Management',
                'short_name': 'Baseline Configuration',
                'description': 'Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.',
                'purpose': 'Configuration baselines ensure that systems are built and maintained according to approved, documented standards. This control prevents unauthorized changes and provides a known-good state for recovery purposes.',
                'business_impact': 'Without proper configuration management, organizations face increased security risks, system instability, and difficulty in troubleshooting. Unauthorized changes can introduce vulnerabilities and compliance violations.',
                'implementation_steps': [
                    'Document approved baseline configurations for all network devices',
                    'Implement version control for configuration files',
                    'Establish change management procedures',
                    'Perform regular configuration audits and drift detection',
                    'Maintain inventory of all system components and their approved configurations'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Compare current configurations against approved baselines',
                        'Document any unauthorized changes found',
                        'Revert unauthorized changes to baseline state',
                        'Update change management procedures if necessary'
                    ],
                    'long_term_measures': [
                        'Implement automated configuration monitoring',
                        'Establish regular configuration backup procedures',
                        'Train staff on proper change management procedures',
                        'Consider configuration management tools (e.g., Ansible, Puppet)'
                    ]
                },
                'check_details': 'Compares current device configuration against approved baseline configuration files to identify unauthorized changes, missing security settings, or configuration drift.',
                'compliance_examples': {
                    'compliant': 'Device configuration matches approved baseline with all required security settings present',
                    'non_compliant': 'Device has unauthorized changes, missing security configurations, or differs from baseline'
                },
                'related_controls': ['CM.L2-3.4.2', 'CM.L2-3.4.6', 'CM.L2-3.4.7'],
                'risk_level': 'Medium'
            },
            'AC.L1-3.1.1': {
                'title': 'AC.L1-3.1.1 - Access Control Policy', 
                'short_name': 'Authorized Access Control',
                'description': 'Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).',
                'purpose': 'This fundamental access control ensures that only legitimate users, processes, and devices can access network systems. It forms the foundation of cybersecurity by preventing unauthorized access that could lead to data breaches, system compromise, or regulatory violations.',
                'business_impact': 'Failure to properly control access can result in data breaches, intellectual property theft, regulatory fines, and loss of customer trust. Unauthorized access is often the first step in cyber attacks.',
                'implementation_steps': [
                    'Deploy centralized authentication systems (TACACS+, RADIUS, or Active Directory)',
                    'Configure network devices to use centralized authentication with local fallback',
                    'Implement role-based access controls with principle of least privilege',
                    'Establish procedures for account provisioning and deprovisioning',
                    'Monitor and log all authentication attempts and access events'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Configure AAA (Authentication, Authorization, Accounting) on all network devices',
                        'Set up TACACS+ or RADIUS servers for centralized authentication',
                        'Configure local user accounts as backup authentication method',
                        'Test authentication failover mechanisms',
                        'Review and update user access permissions'
                    ],
                    'long_term_measures': [
                        'Implement multi-factor authentication where possible',
                        'Establish regular access reviews and account audits',
                        'Deploy privileged access management (PAM) solutions',
                        'Create automated alerts for authentication failures',
                        'Develop incident response procedures for access violations'
                    ]
                },
                'check_details': 'Verifies that AAA authentication is configured with TACACS+ or RADIUS servers, includes local fallback authentication, and that authentication servers are reachable.',
                'compliance_examples': {
                    'compliant': 'AAA authentication configured with "aaa authentication login default group tacacs+ local" and reachable TACACS+ servers',
                    'non_compliant': 'No AAA configuration, missing TACACS+ servers, or no local fallback authentication'
                },
                'related_controls': ['AC.L1-3.1.2', 'AC.L2-3.1.3', 'IA.L1-3.5.1'],
                'risk_level': 'High'
            },
            'AC.L1-3.1.2': {
                'title': 'AC.L1-3.1.2 - Transaction and Function Control',
                'short_name': 'Transaction Limitation',
                'description': 'Limit information system access to the types of transactions and functions that authorized users are permitted to execute.',
                'purpose': 'This control prevents privilege escalation and ensures users can only perform actions appropriate to their role. It reduces the risk of accidental or malicious misuse of system privileges.',
                'business_impact': 'Without proper transaction controls, users might accidentally or intentionally perform actions beyond their authority, potentially causing system outages, data corruption, or security breaches.',
                'implementation_steps': [
                    'Configure enable secret passwords to protect privileged mode access',
                    'Implement user privilege levels (0-15) based on job roles',
                    'Disable insecure protocols like Telnet in favor of SSH',
                    'Configure command authorization to restrict specific commands',
                    'Implement session timeouts and logging for privileged access'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Set strong enable secret passwords on all devices',
                        'Configure user accounts with appropriate privilege levels',
                        'Disable Telnet access and use SSH only for remote management',
                        'Review and update user permissions based on job roles',
                        'Implement session timeouts for privileged access'
                    ],
                    'long_term_measures': [
                        'Deploy command authorization using TACACS+',
                        'Implement just-in-time privileged access',
                        'Regular review of user privilege assignments',
                        'Automated monitoring of privilege escalation attempts',
                        'Training on secure administrative practices'
                    ]
                },
                'check_details': 'Checks for enable secret configuration, user privilege levels, disabled Telnet access, and SSH-only transport input on VTY lines.',
                'compliance_examples': {
                    'compliant': 'Enable secret configured, users have appropriate privilege levels, SSH-only access enabled',
                    'non_compliant': 'Missing enable secret, all users have privilege 15, Telnet enabled alongside SSH'
                },
                'related_controls': ['AC.L1-3.1.1', 'AC.L2-3.1.5', 'IA.L1-3.5.2'],
                'risk_level': 'High'
            },
            'IA.L1-3.5.1': {
                'title': 'IA.L1-3.5.1 - User Identification',
                'short_name': 'User Identification',
                'description': 'Identify information system users, processes acting on behalf of users, or devices.',
                'purpose': 'User identification is the foundation of accountability and audit trails. Without proper identification, it is impossible to trace actions back to specific individuals or processes.',
                'business_impact': 'Poor user identification makes forensic investigations difficult, reduces accountability, and may violate regulatory requirements for audit trails.',
                'implementation_steps': [
                    'Configure unique user accounts for each person requiring access',
                    'Avoid shared or generic accounts except where specifically required',
                    'Implement consistent naming conventions for user accounts',
                    'Ensure all system processes run under identified service accounts',
                    'Log all user identification events for audit purposes'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Create individual user accounts for each administrator',
                        'Eliminate shared accounts where possible',
                        'Implement consistent username formats',
                        'Configure logging for all authentication events',
                        'Review existing accounts and remove unused ones'
                    ],
                    'long_term_measures': [
                        'Integrate with enterprise identity management systems',
                        'Implement automated account lifecycle management',
                        'Regular audits of user account usage',
                        'Establish procedures for account naming and creation',
                        'Deploy identity correlation tools for security monitoring'
                    ]
                },
                'check_details': 'Verifies that individual user accounts are configured rather than relying solely on shared accounts or generic authentication.',
                'compliance_examples': {
                    'compliant': 'Individual username accounts configured for each administrator with unique identifiers',
                    'non_compliant': 'Only shared accounts like "admin" or "cisco" configured for multiple users'
                },
                'related_controls': ['IA.L1-3.5.2', 'AU.L2-3.3.1', 'AU.L2-3.3.2'],
                'risk_level': 'Medium'
            },
            'IA.L1-3.5.2': {
                'title': 'IA.L1-3.5.2 - User Authentication',
                'short_name': 'User Authentication',
                'description': 'Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.',
                'purpose': 'Authentication ensures that users are who they claim to be before granting access to sensitive systems and data. This control prevents unauthorized access through stolen credentials or impersonation.',
                'business_impact': 'Weak authentication mechanisms can lead to unauthorized access, data breaches, and compliance violations. Strong authentication is essential for maintaining system integrity.',
                'implementation_steps': [
                    'Implement strong password policies with complexity requirements',
                    'Use encrypted password storage (secrets instead of passwords)',
                    'Configure multi-factor authentication where supported',
                    'Implement account lockout policies for failed attempts',
                    'Regular password rotation and strength validation'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Replace plaintext passwords with encrypted secrets',
                        'Strengthen password complexity requirements',
                        'Implement account lockout after failed attempts',
                        'Configure password aging and rotation policies',
                        'Review and strengthen existing passwords'
                    ],
                    'long_term_measures': [
                        'Deploy multi-factor authentication solutions',
                        'Implement single sign-on (SSO) where appropriate',
                        'Use certificate-based authentication for devices',
                        'Regular security awareness training on password security',
                        'Deploy password managers for administrative accounts'
                    ]
                },
                'check_details': 'Validates authentication mechanisms including enable secret presence, password strength, and encryption of stored credentials.',
                'compliance_examples': {
                    'compliant': 'Enable secret configured with encrypted storage, strong password policies enforced',
                    'non_compliant': 'Plaintext passwords used, weak passwords, no enable secret configured'
                },
                'related_controls': ['IA.L1-3.5.1', 'IA.L2-3.5.3', 'AC.L1-3.1.1'],
                'risk_level': 'High'
            },
            'SC.L1-3.13.1': {
                'title': 'SC.L1-3.13.1 - Boundary Protection',
                'short_name': 'Network Boundary Protection',
                'description': 'Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.',
                'purpose': 'Boundary protection controls network traffic flow and prevents unauthorized access from external threats. It establishes security perimeters and controls communication between network segments.',
                'business_impact': 'Without proper boundary protection, organizations are vulnerable to external attacks, data exfiltration, and lateral movement by attackers within the network.',
                'implementation_steps': [
                    'Deploy and configure firewalls at network perimeters',
                    'Implement access control lists (ACLs) on network devices',
                    'Configure management access controls and restrictions',
                    'Establish network segmentation and micro-segmentation',
                    'Monitor and log all boundary protection activities'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Configure ACLs on all network interfaces',
                        'Implement management ACLs on VTY lines',
                        'Enable SSH-only management access',
                        'Configure dedicated management interfaces where available',
                        'Review and tighten existing ACL rules'
                    ],
                    'long_term_measures': [
                        'Deploy next-generation firewalls with deep packet inspection',
                        'Implement network segmentation based on business functions',
                        'Deploy intrusion detection and prevention systems',
                        'Establish security monitoring and analytics capabilities',
                        'Regular penetration testing of boundary controls'
                    ]
                },
                'check_details': 'Verifies SSH-only management access, presence and application of ACLs, management interface protections, and VTY access controls.',
                'compliance_examples': {
                    'compliant': 'SSH-only management, ACLs applied to interfaces, management ACLs on VTY lines, dedicated management interface',
                    'non_compliant': 'Telnet enabled, missing ACLs, no management access controls, unprotected management interfaces'
                },
                'related_controls': ['SC.L1-3.13.5', 'SC.L2-3.13.2', 'SI.L1-3.14.1'],
                'risk_level': 'High'
            },
            'SC.L1-3.13.5': {
                'title': 'SC.L1-3.13.5 - Public Access Point Controls',
                'short_name': 'DMZ/Public Access Separation',
                'description': 'Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).',
                'purpose': 'This control ensures that publicly accessible systems (like DMZ servers) are properly isolated and controlled. It prevents unauthorized access to internal networks through public-facing services.',
                'business_impact': 'Improperly secured public access points can provide attackers with entry into internal networks, leading to data breaches and system compromise.',
                'implementation_steps': [
                    'Identify all public-facing interfaces and systems',
                    'Implement strict ACLs using deny-all, permit-by-exception approach',
                    'Configure DMZ network segmentation',
                    'Apply appropriate security controls to public access points',
                    'Monitor and log all public access point activities'
                ],
                'remediation_guidance': {
                    'immediate_actions': [
                        'Apply ACLs to all DMZ and public-facing interfaces',
                        'Configure deny-all, permit-by-exception rules',
                        'Review and tighten existing public access controls',
                        'Implement network segmentation for public services',
                        'Enable comprehensive logging for public access points'
                    ],
                    'long_term_measures': [
                        'Deploy web application firewalls for public web services',
                        'Implement DDoS protection for public-facing systems',
                        'Regular security assessments of public access points',
                        'Automated threat detection for public interfaces',
                        'Incident response procedures for public access incidents'
                    ]
                },
                'check_details': 'Identifies DMZ and public-facing interfaces and verifies that appropriate ACLs are applied to control and restrict access.',
                'compliance_examples': {
                    'compliant': 'All DMZ interfaces have restrictive ACLs applied with specific permit rules for required services only',
                    'non_compliant': 'DMZ interfaces without ACLs, overly permissive rules, or missing access controls on public-facing systems'
                },
                'related_controls': ['SC.L1-3.13.1', 'SC.L2-3.13.3', 'SI.L2-3.14.2'],
                'risk_level': 'High'
            }
        }
    
    def generate_dashboard(self, results_list, output_path="enhanced_compliance_dashboard.html"):
        """Generate comprehensive HTML dashboard from actual compliance results."""
        
        # Process the results to get dashboard data
        dashboard_data = self._process_results(results_list)
        
        # Generate the complete HTML
        html_content = self._create_html_dashboard(dashboard_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _process_results(self, results_list):
        """Process compliance results into dashboard data structure."""
        total_devices = len(results_list)
        if total_devices == 0:
            return {
                'total_devices': 0,
                'compliant_devices': 0,
                'compliance_rate': 0,
                'timestamp': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
                'controls': {},
                'devices': [],
                'remediation_priorities': [],
                'risk_level': 'Unknown'
            }
        
        compliant_devices = sum(1 for r in results_list if r.get('compliant', False))
        compliance_rate = (compliant_devices / total_devices) * 100
        
        # Process control statistics
        controls_data = {}
        for control_id, control_info in self.cmmc_controls.items():
            passed = sum(1 for r in results_list 
                        if r.get('checks', {}).get(control_id, {}).get('passed', False))
            failed = total_devices - passed
            
            # Calculate failure reasons
            failure_reasons = {}
            for result in results_list:
                control_data = result.get('checks', {}).get(control_id, {})
                if not control_data.get('passed', True):
                    issues = self._extract_control_issues(control_id, control_data)
                    for issue in issues:
                        failure_reasons[issue] = failure_reasons.get(issue, 0) + 1
            
            controls_data[control_id] = {
                'passed': passed,
                'failed': failed,
                'compliance_rate': (passed / total_devices * 100) if total_devices > 0 else 0,
                'title': control_info['title'],
                'short_name': control_info['short_name'],
                'description': control_info['description'],
                'purpose': control_info['purpose'],
                'business_impact': control_info['business_impact'],
                'implementation_steps': control_info['implementation_steps'],
                'remediation_guidance': control_info['remediation_guidance'],
                'check_details': control_info['check_details'],
                'compliance_examples': control_info['compliance_examples'],
                'risk_level': control_info['risk_level'],
                'failure_reasons': failure_reasons,
                'related_controls': control_info.get('related_controls', [])
            }
        
        # Process device data
        devices_data = []
        for result in results_list:
            device_data = {
                'hostname': result.get('hostname', 'Unknown'),
                'vendor': result.get('vendor_display', 'Unknown'),
                'compliant': result.get('compliant', False),
                'score': self._calculate_device_score(result),
                'risk_level': self._calculate_device_risk_level(result),
                'issues': self._extract_device_issues(result)
            }
            devices_data.append(device_data)
        
        # Generate remediation priorities
        remediation_priorities = self._generate_remediation_priorities(results_list)
        
        # Calculate overall risk level
        risk_level = self._calculate_overall_risk_level(results_list)
        
        return {
            'total_devices': total_devices,
            'compliant_devices': compliant_devices,
            'compliance_rate': compliance_rate,
            'timestamp': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'controls': controls_data,
            'devices': devices_data,
            'remediation_priorities': remediation_priorities,
            'risk_level': risk_level
        }
    
    def _extract_control_issues(self, control_id, control_data):
        """Extract specific issues for a control based on its failed state."""
        issues = []
        
        if control_id == 'AC.L1-3.1.1':
            if not control_data.get('aaa_configured'):
                issues.append("AAA authentication not configured")
            if not control_data.get('tacacs_servers'):
                issues.append("No TACACS+ servers configured")
                
        elif control_id == 'AC.L1-3.1.2':
            if not control_data.get('enable_secret_present'):
                issues.append("Enable secret not configured")
            if not control_data.get('no_telnet'):
                issues.append("Telnet access enabled (security risk)")
                
        elif control_id == 'IA.L1-3.5.1':
            if not control_data.get('user_identification'):
                issues.append("Individual user accounts not configured")
                
        elif control_id == 'IA.L1-3.5.2':
            if not control_data.get('authentication_configured'):
                issues.append("Authentication mechanisms insufficient")
            if control_data.get('weak_passwords'):
                issues.append("Weak or plaintext passwords detected")
                
        elif control_id == 'SC.L1-3.13.1':
            if not control_data.get('ssh_mgmt'):
                issues.append("SSH management not properly configured")
            if not control_data.get('acls_present_and_applied'):
                issues.append("Access control lists missing or not applied")
                
        elif control_id == 'SC.L1-3.13.5':
            dmz_issues = control_data.get('dmz_interfaces_without_acl', [])
            if dmz_issues:
                issues.append(f"DMZ interfaces without ACL protection: {len(dmz_issues)}")
                
        elif control_id == 'CM.L1-3.4.1':
            missing = control_data.get('missing_lines', [])
            extra = control_data.get('extra_lines', [])
            if missing:
                issues.append(f"Missing baseline configurations: {len(missing)} items")
            if extra:
                issues.append(f"Unauthorized configuration changes: {len(extra)} items")
        
        return issues if issues else ["Control requirements not met"]
    
    def _calculate_device_score(self, result):
        """Calculate device compliance score."""
        checks = result.get('checks', {})
        if not checks:
            return 0
        
        total_controls = len(checks)
        passed_controls = sum(1 for check in checks.values() if check.get('passed', False))
        
        return int((passed_controls / total_controls) * 100)
    
    def _calculate_device_risk_level(self, result):
        """Calculate device risk level."""
        checks = result.get('checks', {})
        risk_score = 0
        
        for control_id, control_data in checks.items():
            if not control_data.get('passed', True):
                control_info = self.cmmc_controls.get(control_id, {})
                if control_info.get('risk_level') == 'High':
                    risk_score += 30
                elif control_info.get('risk_level') == 'Medium':
                    risk_score += 15
                else:
                    risk_score += 5
        
        if risk_score >= 60:
            return 'Critical'
        elif risk_score >= 30:
            return 'High'
        elif risk_score >= 15:
            return 'Medium'
        elif risk_score > 0:
            return 'Low'
        else:
            return 'Minimal'
    
    def _extract_device_issues(self, result):
        """Extract all issues for a device."""
        issues = []
        checks = result.get('checks', {})
        
        for control_id, control_data in checks.items():
            if not control_data.get('passed', True):
                control_issues = self._extract_control_issues(control_id, control_data)
                issues.extend(control_issues)
        
        return issues
    
    def _generate_remediation_priorities(self, results_list):
        """Generate prioritized remediation recommendations."""
        priorities = []
        
        # Analyze common issues across all devices
        issue_analysis = {}
        total_devices = len(results_list)
        
        for result in results_list:
            checks = result.get('checks', {})
            for control_id, control_data in checks.items():
                if not control_data.get('passed', True):
                    control_info = self.cmmc_controls.get(control_id, {})
                    issues = self._extract_control_issues(control_id, control_data)
                    
                    for issue in issues:
                        if issue not in issue_analysis:
                            issue_analysis[issue] = {
                                'count': 0,
                                'control_id': control_id,
                                'control_name': control_info.get('short_name', control_id),
                                'risk_level': control_info.get('risk_level', 'Medium'),
                                'remediation': control_info.get('remediation_guidance', {})
                            }
                        issue_analysis[issue]['count'] += 1
        
        # Sort by impact and frequency
        sorted_issues = sorted(issue_analysis.items(), 
                             key=lambda x: (
                                 x[1]['risk_level'] == 'High',
                                 x[1]['count'],
                                 x[1]['control_id']
                             ), reverse=True)
        
        for issue, data in sorted_issues[:10]:  # Top 10 issues
            percentage = (data['count'] / total_devices) * 100
            
            priority_level = 'Critical' if data['risk_level'] == 'High' and percentage > 50 else \
                           'High' if data['risk_level'] == 'High' or percentage > 30 else \
                           'Medium'
            
            priorities.append({
                'priority': priority_level,
                'issue': issue,
                'control': data['control_name'],
                'control_id': data['control_id'],
                'affected_devices': data['count'],
                'percentage': percentage,
                'immediate_actions': data['remediation'].get('immediate_actions', []),
                'long_term_measures': data['remediation'].get('long_term_measures', [])
            })
        
        return priorities
    
    def _calculate_overall_risk_level(self, results_list):
        """Calculate overall organizational risk level."""
        if not results_list:
            return 'Unknown'
        
        compliance_rate = (sum(1 for r in results_list if r.get('compliant', False)) / len(results_list)) * 100
        
        # Count critical control failures
        critical_failures = 0
        for result in results_list:
            checks = result.get('checks', {})
            for control_id, control_data in checks.items():
                if not control_data.get('passed', True):
                    control_info = self.cmmc_controls.get(control_id, {})
                    if control_info.get('risk_level') == 'High':
                        critical_failures += 1
        
        if compliance_rate < 50 or critical_failures > 5:
            return 'Critical'
        elif compliance_rate < 75 or critical_failures > 2:
            return 'High'
        elif compliance_rate < 90 or critical_failures > 0:
            return 'Medium'
        else:
            return 'Low'
    
    def _create_html_dashboard(self, data):
        """Create the complete HTML dashboard with dynamic content."""
        return self._generate_html_template(data)
    
    def _generate_html_template(self, data):
        """Generate the complete HTML template with dynamic data."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMMC 2.0 Level 1 Compliance Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    
    {self._get_dashboard_css()}
</head>
<body>
    <div class="dashboard-container">
        {self._generate_header_html(data)}
        {self._generate_stats_grid_html(data)}
        {self._generate_main_content_html(data)}
        {self._generate_modal_html()}
    </div>
    
    {self._generate_javascript(data)}
</body>
</html>"""

    def _generate_header_html(self, data):
        """Generate the dashboard header with actual data."""
        compliance_badge_class = self._get_compliance_badge_class(data['compliance_rate'])
        
        return f"""
        <div class="dashboard-header fade-in">
            <div class="header-content">
                <div>
                    <h1 class="dashboard-title">
                        <i data-feather="shield-check"></i>
                        CMMC 2.0 Level 1 Compliance Dashboard
                    </h1>
                    <p style="color: var(--text-secondary); margin-top: 0.5rem; font-size: 1.1rem;">
                        Cybersecurity Maturity Model Certification Assessment Report
                    </p>
                </div>
                <div class="header-meta">
                    <div style="font-size: 0.9rem; font-weight: 500;">
                        Generated on {data['timestamp']}
                    </div>
                    <div class="compliance-badge {compliance_badge_class}">
                        {data['compliance_rate']:.1f}% Compliant
                    </div>
                </div>
            </div>
        </div>"""

    def _generate_stats_grid_html(self, data):
        """Generate the statistics grid with actual data."""
        risk_color = self._get_risk_color_class(data['risk_level'])
        
        return f"""
        <div class="stats-grid fade-in">
            <div class="stat-card">
                <div class="stat-number" style="color: var(--success-color);">
                    <i data-feather="check-circle"></i>
                    {data['compliant_devices']}
                </div>
                <div class="stat-label">Compliant Devices</div>
                <div class="stat-detail">
                    <i data-feather="trending-up"></i>
                    {data['compliance_rate']:.1f}% of total inventory
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number" style="color: var(--danger-color);">
                    <i data-feather="alert-circle"></i>
                    {data['total_devices'] - data['compliant_devices']}
                </div>
                <div class="stat-label">Non-Compliant Devices</div>
                <div class="stat-detail">
                    <i data-feather="alert-triangle"></i>
                    {len(data['remediation_priorities'])} priority issues
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number {risk_color}">
                    <i data-feather="activity"></i>
                    {data['risk_level']}
                </div>
                <div class="stat-label">Risk Level</div>
                <div class="stat-detail">
                    <i data-feather="shield"></i>
                    Overall security posture
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number" style="color: var(--info-color);">
                    <i data-feather="server"></i>
                    {data['total_devices']}
                </div>
                <div class="stat-label">Total Devices</div>
                <div class="stat-detail">
                    <i data-feather="database"></i>
                    Network inventory assessed
                </div>
            </div>
        </div>"""

    def _generate_main_content_html(self, data):
        """Generate the main content area with controls and remediation."""
        return f"""
        <div class="main-content">
            <div style="display: flex; flex-direction: column; gap: 2rem;">
                <!-- CMMC Controls Assessment -->
                <div class="card fade-in">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i data-feather="clipboard-list"></i>
                            CMMC 2.0 Level 1 Controls Assessment
                        </h2>
                    </div>
                    <div class="card-content">
                        <div class="controls-grid">
                            {self._generate_control_cards_html(data['controls'])}
                        </div>
                    </div>
                </div>

                <!-- Device Compliance Status -->
                <div class="card fade-in">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i data-feather="monitor"></i>
                            Device Compliance Status
                        </h2>
                    </div>
                    <div class="card-content">
                        <div class="devices-grid">
                            {self._generate_device_cards_html(data['devices'])}
                        </div>
                    </div>
                </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 2rem;">
                <!-- Priority Remediation -->
                <div class="card fade-in">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i data-feather="tool"></i>
                            Priority Remediation
                        </h3>
                    </div>
                    <div class="card-content">
                        {self._generate_remediation_html(data['remediation_priorities'])}
                    </div>
                </div>
            </div>
        </div>"""

    def _generate_control_cards_html(self, controls):
        """Generate HTML for control cards with actual data."""
        cards_html = ""
        for control_id, control_data in controls.items():
            compliance_rate = control_data['compliance_rate']
            
            if compliance_rate >= 100:
                rate_class = "rate-excellent"
                card_class = "passed"
                status_class = "status-pass"
                status_icon = "check-circle"
                status_text = "COMPLIANT"
            else:
                rate_class = "rate-poor" if compliance_rate < 50 else "rate-warning"
                card_class = "failed"
                status_class = "status-fail"
                status_icon = "x-circle"
                status_text = "NON-COMPLIANT"
            
            # Generate failure reasons if any
            failure_reasons_html = ""
            if control_data.get('failure_reasons'):
                failure_reasons_html = "<div style='margin-top: 1rem;'><strong>Common Issues:</strong><br>"
                for reason, count in list(control_data['failure_reasons'].items())[:3]:
                    failure_reasons_html += f"<small>• {reason} ({count} devices)</small><br>"
                failure_reasons_html += "</div>"
            
            cards_html += f"""
            <div class="control-card {card_class} clickable" onclick="showControlDetails('{control_id}')">
                <div class="control-header">
                    <div>
                        <div class="control-title">{control_data['short_name']}</div>
                        <div class="control-id">{control_id}</div>
                        <div class="control-description">{control_data['description'][:120]}...</div>
                    </div>
                    <div class="control-status {status_class}">
                        <i data-feather="{status_icon}"></i>
                        {status_text}
                    </div>
                </div>
                <div class="control-stats">
                    <div>
                        <span style="color: var(--success-color); font-weight: 600;">
                            <i data-feather="check" style="width: 14px; height: 14px;"></i> 
                            {control_data['passed']} passing
                        </span>
                        <span style="margin-left: 1rem; color: var(--danger-color); font-weight: 600;">
                            <i data-feather="x" style="width: 14px; height: 14px;"></i> 
                            {control_data['failed']} failing
                        </span>
                    </div>
                    <div class="compliance-rate {rate_class}">
                        {compliance_rate:.0f}%
                    </div>
                </div>
                {failure_reasons_html}
                <div style="margin-top: 1rem; font-size: 0.875rem; color: var(--info-color);">
                    <i data-feather="info" style="width: 14px; height: 14px;"></i>
                    Click for detailed implementation guidance
                </div>
            </div>
            """
        
        return cards_html

    def _generate_device_cards_html(self, devices):
        """Generate HTML for device cards with actual data."""
        cards_html = ""
        for device in devices:
            compliance_class = "device-compliant" if device['compliant'] else "device-non-compliant"
            risk_class = f"risk-{device['risk_level'].lower()}"
            
            # Generate issues display
            issues_html = ""
            if device['issues']:
                issues_html = '<div class="device-issues">'
                issues_html += '<div class="issues-header">Issues Found:</div>'
                issues_html += '<div class="issue-list">'
                
                for issue in device['issues'][:5]:  # Show first 5 issues
                    issues_html += f'<span class="issue-tag">{issue[:30]}...</span>'
                
                if len(device['issues']) > 5:
                    issues_html += f'<span class="issue-tag">+{len(device["issues"]) - 5} more</span>'
                
                issues_html += '</div></div>'
            
            cards_html += f"""
            <div class="device-card">
                <div class="device-header">
                    <div>
                        <div class="device-name">{device['hostname']}</div>
                        <div class="device-vendor">{device['vendor']}</div>
                    </div>
                    <div class="device-status {compliance_class}">
                        <i data-feather="{'check-circle' if device['compliant'] else 'x-circle'}"></i>
                        {'COMPLIANT' if device['compliant'] else 'NON-COMPLIANT'}
                    </div>
                </div>
                
                <div class="device-metrics">
                    <div class="metric">
                        <div class="metric-value">{device['score']}</div>
                        <div class="metric-label">Score</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value {risk_class}">{device['risk_level']}</div>
                        <div class="metric-label">Risk Level</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">{len(device['issues'])}</div>
                        <div class="metric-label">Issues</div>
                    </div>
                </div>
                
                {issues_html}
            </div>
            """
        
        return cards_html

    def _generate_remediation_html(self, priorities):
        """Generate HTML for remediation priorities with actual data."""
        if not priorities:
            return "<p>No remediation priorities identified. All devices are compliant!</p>"
        
        remediation_html = ""
        for priority in priorities:
            priority_class = f"priority-{priority['priority'].lower()}"
            
            # Generate immediate actions
            actions_html = ""
            for action in priority.get('immediate_actions', [])[:3]:
                actions_html += f'<div class="action-item">{action}</div>'
            
            remediation_html += f"""
            <div class="remediation-card">
                <div class="remediation-header">
                    <div class="remediation-title">{priority['issue']}</div>
                    <div class="priority-badge {priority_class}">{priority['priority']}</div>
                </div>
                <div class="remediation-description">
                    <strong>Control:</strong> {priority['control']} ({priority['control_id']})<br>
                    <strong>Impact:</strong> {priority['affected_devices']} devices ({priority['percentage']:.1f}%)
                </div>
                <div class="remediation-actions">
                    <div class="actions-title">Immediate Actions:</div>
                    <div class="action-list">
                        {actions_html}
                    </div>
                </div>
            </div>
            """
        
        return remediation_html

    def _generate_modal_html(self):
        """Generate the modal for control details."""
        return """
        <div id="controlModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="modalTitle" class="modal-title"></h3>
                    <button class="close" onclick="closeModal()">&times;</button>
                </div>
                <div class="modal-body" id="modalBody">
                    <!-- Content populated by JavaScript -->
                </div>
            </div>
        </div>"""
    
    def _get_dashboard_css(self):
        """Return the complete CSS for the dashboard."""
        return """
        <style>
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
            --light-gray: #f8fafc;
            --medium-gray: #e2e8f0;
            --dark-gray: #334155;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border-radius: 16px;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard-header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-xl);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .dashboard-title {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .header-meta {
            text-align: right;
            color: var(--text-secondary);
        }
        
        .compliance-badge {
            display: inline-block;
            margin-top: 0.5rem;
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            font-weight: 700;
            font-size: 1rem;
            box-shadow: var(--shadow-md);
        }
        
        .badge-excellent { background: linear-gradient(135deg, var(--success-color), #059669); color: white; }
        .badge-good { background: linear-gradient(135deg, #10b981, #047857); color: white; }
        .badge-warning { background: linear-gradient(135deg, var(--warning-color), #d97706); color: white; }
        .badge-poor { background: linear-gradient(135deg, var(--danger-color), #dc2626); color: white; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            padding: 2rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--success-color));
        }
        
        .stat-number {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 1rem;
        }
        
        .stat-detail {
            font-size: 0.875rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }
        
        .card-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--medium-gray);
            background: linear-gradient(135deg, var(--light-gray), rgba(255, 255, 255, 0.8));
        }
        
        .card-title {
            font-size: 1.375rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .card-content {
            padding: 1.5rem;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .controls-grid, .devices-grid {
            display: grid;
            gap: 1.5rem;
        }
        
        .control-card, .device-card {
            border: 2px solid var(--medium-gray);
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.8), rgba(248, 250, 252, 0.9));
        }
        
        .control-card:hover, .device-card:hover {
            border-color: var(--primary-color);
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
        }
        
        .control-card.failed {
            border-color: var(--danger-color);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.05), rgba(254, 226, 226, 0.3));
        }
        
        .control-card.passed {
            border-color: var(--success-color);
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.05), rgba(209, 250, 229, 0.3));
        }
        
        .control-header, .device-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        
        .control-title, .device-name {
            font-weight: 700;
            font-size: 1.125rem;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }
        
        .control-id, .device-vendor {
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .control-status, .device-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            font-size: 0.875rem;
            padding: 0.5rem 1rem;
            border-radius: 50px;
        }
        
        .status-pass, .device-compliant {
            background: rgba(16, 185, 129, 0.1);
            color: #065f46;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .status-fail, .device-non-compliant {
            background: rgba(239, 68, 68, 0.1);
            color: #991b1b;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .control-description {
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 1rem;
        }
        
        .control-stats {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .compliance-rate {
            font-weight: 700;
            font-size: 1.25rem;
        }
        
        .rate-excellent { color: var(--success-color); }
        .rate-good { color: #10b981; }
        .rate-warning { color: var(--warning-color); }
        .rate-poor { color: var(--danger-color); }
        
        .device-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .metric {
            text-align: center;
            padding: 0.75rem;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .metric-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .device-issues {
            margin-top: 1rem;
        }
        
        .issues-header {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        
        .issue-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        .issue-tag {
            background: rgba(239, 68, 68, 0.1);
            color: #991b1b;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .remediation-card {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.05), rgba(147, 197, 253, 0.1));
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .remediation-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        
        .remediation-title {
            font-weight: 700;
            color: var(--text-primary);
            font-size: 1.1rem;
        }
        
        .priority-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .priority-critical {
            background: rgba(239, 68, 68, 0.1);
            color: #991b1b;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .priority-high {
            background: rgba(245, 158, 11, 0.1);
            color: #92400e;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .priority-medium {
            background: rgba(59, 130, 246, 0.1);
            color: #1e40af;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        
        .remediation-description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.5;
        }
        
        .remediation-actions {
            background: rgba(255, 255, 255, 0.7);
            border-radius: 8px;
            padding: 1rem;
        }
        
        .actions-title {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.75rem;
            font-size: 0.9rem;
        }
        
        .action-list {
            list-style: none;
            padding: 0;
        }
        
        .action-item {
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(226, 232, 240, 0.5);
            display: flex;
            align-items: flex-start;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .action-item:last-child {
            border-bottom: none;
        }
        
        .action-item::before {
            content: "→";
            color: var(--primary-color);
            font-weight: 600;
            flex-shrink: 0;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.6);
            backdrop-filter: blur(8px);
        }
        
        .modal-content {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            margin: 2% auto;
            padding: 0;
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 900px;
            box-shadow: var(--shadow-xl);
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .modal-header {
            padding: 2rem;
            border-bottom: 1px solid var(--medium-gray);
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin: 0;
        }
        
        .modal-body {
            padding: 2rem;
        }
        
        .close {
            color: white;
            font-size: 2rem;
            font-weight: bold;
            cursor: pointer;
            border: none;
            background: none;
            padding: 0.5rem;
            border-radius: 8px;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
        }
        
        .close:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .clickable {
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .clickable:hover {
            transform: translateY(-1px);
        }
        
        .fade-in {
            animation: fadeIn 0.6s ease-out;
        }
        
        .risk-critical { color: #7f1d1d; }
        .risk-high { color: var(--danger-color); }
        .risk-medium { color: var(--warning-color); }
        .risk-low { color: var(--info-color); }
        .risk-minimal { color: var(--success-color); }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @media (max-width: 1200px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .dashboard-container {
                padding: 1rem;
            }
        }
        
        @media (max-width: 768px) {
            .dashboard-title {
                font-size: 2rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>"""
    
    def _generate_javascript(self, data):
        """Generate JavaScript for dashboard interactivity."""
        return f"""
        <script>
        // Initialize Feather icons
        feather.replace();

        // Control details data
        const controlDetails = {json.dumps({k: v for k, v in data['controls'].items()})};

        // Show control details modal
        function showControlDetails(controlId) {{
            const control = controlDetails[controlId];
            if (!control) return;

            document.getElementById('modalTitle').textContent = control.title;
            document.getElementById('modalBody').innerHTML = `
                <div class="control-details">
                    <div class="detail-section">
                        <h4><i data-feather="info"></i> Description & Purpose</h4>
                        <p><strong>Description:</strong> ${{control.description}}</p>
                        <p><strong>Purpose:</strong> ${{control.purpose}}</p>
                        <p><strong>Business Impact:</strong> ${{control.business_impact}}</p>
                    </div>

                    <div class="detail-section">
                        <h4><i data-feather="list"></i> Implementation Steps</h4>
                        <ul>
                            ${{control.implementation_steps.map(step => `<li>${{step}}</li>`).join('')}}
                        </ul>
                    </div>

                    <div class="detail-section remediation-section">
                        <h4><i data-feather="tool"></i> Remediation Guidance</h4>
                        <p><strong>Immediate Actions:</strong></p>
                        <ul>
                            ${{control.remediation_guidance.immediate_actions.map(action => `<li>${{action}}</li>`).join('')}}
                        </ul>
                        <p><strong>Long-term Measures:</strong></p>
                        <ul>
                            ${{control.remediation_guidance.long_term_measures.map(measure => `<li>${{measure}}</li>`).join('')}}
                        </ul>
                    </div>

                    <div class="detail-section">
                        <h4><i data-feather="search"></i> What This Check Verifies</h4>
                        <p>${{control.check_details}}</p>
                    </div>

                    <div class="detail-section">
                        <h4><i data-feather="check-square"></i> Compliance Examples</h4>
                        <div class="examples-grid">
                            <div class="example-card example-compliant">
                                <div class="example-title">✅ Compliant Example</div>
                                <p>${{control.compliance_examples.compliant}}</p>
                            </div>
                            <div class="example-card example-non-compliant">
                                <div class="example-title">❌ Non-Compliant Example</div>
                                <p>${{control.compliance_examples.non_compliant}}</p>
                            </div>
                        </div>
                    </div>

                    <div class="detail-section impact-section">
                        <h4><i data-feather="bar-chart-2"></i> Compliance Statistics</h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                            <div style="text-align: center; padding: 1rem; background: rgba(16, 185, 129, 0.1); border-radius: 8px;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #065f46;">${{control.passed}}</div>
                                <div style="color: #065f46; font-size: 0.875rem;">Compliant</div>
                            </div>
                            <div style="text-align: center; padding: 1rem; background: rgba(239, 68, 68, 0.1); border-radius: 8px;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #991b1b;">${{control.failed}}</div>
                                <div style="color: #991b1b; font-size: 0.875rem;">Non-Compliant</div>
                            </div>
                            <div style="text-align: center; padding: 1rem; background: rgba(59, 130, 246, 0.1); border-radius: 8px;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #1e40af;">${{control.compliance_rate.toFixed(1)}}%</div>
                                <div style="color: #1e40af; font-size: 0.875rem;">Rate</div>
                            </div>
                        </div>
                    </div>

                    ${{control.related_controls && control.related_controls.length > 0 ? `
                    <div class="detail-section">
                        <h4><i data-feather="link"></i> Related Controls</h4>
                        <p>This control is related to: ${{control.related_controls.join(', ')}}</p>
                    </div>
                    ` : ''}}
                </div>
            `;

            // Re-initialize feather icons in modal
            feather.replace();
            
            document.getElementById('controlModal').style.display = 'block';
        }}

        // Close modal
        function closeModal() {{
            document.getElementById('controlModal').style.display = 'none';
        }}

        // Close modal when clicking outside
        window.onclick = function(event) {{
            const modal = document.getElementById('controlModal');
            if (event.target === modal) {{
                modal.style.display = 'none';
            }}
        }}

        // Add fade-in animation on scroll
        const observerOptions = {{
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        }};

        const observer = new IntersectionObserver((entries) => {{
            entries.forEach(entry => {{
                if (entry.isIntersecting) {{
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }}
            }});
        }}, observerOptions);

        document.querySelectorAll('.fade-in').forEach(el => {{
            el.style.opacity = '0';
            el.style.transform = 'translateY(20px)';
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(el);
        }});
        </script>"""
    
    def _get_compliance_badge_class(self, rate):
        """Get CSS class for compliance badge based on rate."""
        if rate >= 95:
            return "badge-excellent"
        elif rate >= 85:
            return "badge-good" 
        elif rate >= 70:
            return "badge-warning"
        else:
            return "badge-poor"
    
    def _get_risk_color_class(self, risk_level):
        """Get CSS class for risk level coloring."""
        return {
            'Minimal': 'risk-minimal',
            'Low': 'risk-low',
            'Medium': 'risk-medium', 
            'High': 'risk-high',
            'Critical': 'risk-critical'
        }.get(risk_level, 'risk-medium')


# Example usage function to integrate with your existing code
def generate_enhanced_dashboard_from_results(results_list, output_path="enhanced_compliance_dashboard.html"):
    """
    Main function to generate enhanced dashboard from compliance results.
    
    Args:
        results_list: List of compliance check results from your scanner
        output_path: Path where to save the HTML dashboard
    
    Returns:
        Path to the generated dashboard
    """
    dashboard = EnhancedCMMCDashboard()
    return dashboard.generate_dashboard(results_list, output_path)


# Integration example for your existing codebase
if __name__ == "__main__":
    # Example of how to use this with your existing compliance results
    sample_results = [
        {
            'hostname': 'router-01',
            'vendor_display': 'Cisco IOS',
            'compliant': False,
            'checks': {
                'AC.L1-3.1.1': {
                    'passed': True,
                    'aaa_configured': True,
                    'tacacs_servers': ['192.168.1.100']
                },
                'AC.L1-3.1.2': {
                    'passed': False,
                    'enable_secret_present': False,
                    'no_telnet': True
                },
                'IA.L1-3.5.1': {
                    'passed': True,
                    'user_identification': True
                },
                'IA.L1-3.5.2': {
                    'passed': True,
                    'authentication_configured': True
                },
                'SC.L1-3.13.1': {
                    'passed': True,
                    'acls_present_and_applied': True
                },
                'SC.L1-3.13.5': {
                    'passed': True,
                    'dmz_interfaces_without_acl': []
                },
                'CM.L1-3.4.1': {
                    'passed': True,
                    'missing_lines': [],
                    'extra_lines': []
                }
            }
        },
        {
            'hostname': 'switch-01',
            'vendor_display': 'Cisco IOS',
            'compliant': True,
            'checks': {
                'AC.L1-3.1.1': {
                    'passed': True,
                    'aaa_configured': True,
                    'tacacs_servers': ['192.168.1.100']
                },
                'AC.L1-3.1.2': {
                    'passed': True,
                    'enable_secret_present': True,
                    'no_telnet': True
                },
                'IA.L1-3.5.1': {
                    'passed': True,
                    'user_identification': True
                },
                'IA.L1-3.5.2': {
                    'passed': True,
                    'authentication_configured': True
                },
                'SC.L1-3.13.1': {
                    'passed': True,
                    'acls_present_and_applied': True
                },
                'SC.L1-3.13.5': {
                    'passed': True,
                    'dmz_interfaces_without_acl': []
                },
                'CM.L1-3.4.1': {
                    'passed': True,
                    'missing_lines': [],
                    'extra_lines': []
                }
            }
        }
    ]
    
    # Generate dashboard
    dashboard_path = generate_enhanced_dashboard_from_results(sample_results, "test_dashboard.html")
    print(f"Enhanced dashboard generated: {dashboard_path}")