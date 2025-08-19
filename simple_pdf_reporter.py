"""Enhanced PDF reporter that matches the dashboard design and content structure."""

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus.flowables import HRFlowable
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from datetime import datetime
from pathlib import Path
import json

class EnhancedPDFReporter:
    """Enhanced PDF reporter that closely matches the dashboard design and content."""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
        # Load CMMC control definitions (matching dashboard)
        self.cmmc_controls = self._load_cmmc_definitions()
    
    def setup_custom_styles(self):
        """Set up custom styles that match the dashboard design."""
        # Title style (matching dashboard header)
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=12,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            spaceAfter=20,
            textColor=colors.HexColor('#64748b'),
            fontName='Helvetica',
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2563eb'),
            fontName='Helvetica-Bold',
            leftIndent=0
        ))
        
        # Control title style
        self.styles.add(ParagraphStyle(
            name='ControlTitle',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=6,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold'
        ))
        
        # Control description style
        self.styles.add(ParagraphStyle(
            name='ControlDescription',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            textColor=colors.HexColor('#64748b'),
            fontName='Helvetica'
        ))
        
        # Stats number style
        self.styles.add(ParagraphStyle(
            name='StatsNumber',
            parent=self.styles['Normal'],
            fontSize=18,
            spaceAfter=4,
            textColor=colors.HexColor('#2563eb'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        # Stats label style
        self.styles.add(ParagraphStyle(
            name='StatsLabel',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=10,
            textColor=colors.HexColor('#64748b'),
            fontName='Helvetica',
            alignment=TA_CENTER
        ))
        
        # Device name style
        self.styles.add(ParagraphStyle(
            name='DeviceName',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=2,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold'
        ))
        
        # Issue text style
        self.styles.add(ParagraphStyle(
            name='IssueText',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=2,
            textColor=colors.HexColor('#ef4444'),
            fontName='Helvetica',
            leftIndent=12
        ))
        
        # Remediation style
        self.styles.add(ParagraphStyle(
            name='RemediationText',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=4,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica',
            leftIndent=12
        ))
    
    def _load_cmmc_definitions(self):
        """Load CMMC control definitions matching the dashboard."""
        return {
            'CM.L1-3.4.1': {
                'title': 'CM.L1-3.4.1 - Configuration Management',
                'short_name': 'Baseline Configuration',
                'description': 'Establish and maintain baseline configurations and inventories of organizational systems.',
                'purpose': 'Configuration baselines ensure that systems are built and maintained according to approved, documented standards.',
                'business_impact': 'Without proper configuration management, organizations face increased security risks, system instability, and difficulty in troubleshooting.',
                'risk_level': 'Medium'
            },
            'AC.L1-3.1.1': {
                'title': 'AC.L1-3.1.1 - Access Control Policy', 
                'short_name': 'Authorized Access Control',
                'description': 'Limit information system access to authorized users, processes acting on behalf of authorized users, or devices.',
                'purpose': 'This fundamental access control ensures that only legitimate users, processes, and devices can access network systems.',
                'business_impact': 'Failure to properly control access can result in data breaches, intellectual property theft, regulatory fines, and loss of customer trust.',
                'risk_level': 'High'
            },
            'AC.L1-3.1.2': {
                'title': 'AC.L1-3.1.2 - Transaction and Function Control',
                'short_name': 'Transaction Limitation',
                'description': 'Limit information system access to the types of transactions and functions that authorized users are permitted to execute.',
                'purpose': 'This control prevents privilege escalation and ensures users can only perform actions appropriate to their role.',
                'business_impact': 'Without proper transaction controls, users might accidentally or intentionally perform actions beyond their authority.',
                'risk_level': 'High'
            },
            'IA.L1-3.5.1': {
                'title': 'IA.L1-3.5.1 - User Identification',
                'short_name': 'User Identification',
                'description': 'Identify information system users, processes acting on behalf of users, or devices.',
                'purpose': 'User identification is the foundation of accountability and audit trails.',
                'business_impact': 'Poor user identification makes forensic investigations difficult, reduces accountability, and may violate regulatory requirements.',
                'risk_level': 'Medium'
            },
            'IA.L1-3.5.2': {
                'title': 'IA.L1-3.5.2 - User Authentication',
                'short_name': 'User Authentication',
                'description': 'Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.',
                'purpose': 'Authentication ensures that users are who they claim to be before granting access to sensitive systems and data.',
                'business_impact': 'Weak authentication mechanisms can lead to unauthorized access, data breaches, and compliance violations.',
                'risk_level': 'High'
            },
            'SC.L1-3.13.1': {
                'title': 'SC.L1-3.13.1 - Boundary Protection',
                'short_name': 'Network Boundary Protection',
                'description': 'Monitor, control, and protect organizational communications at the external boundaries and key internal boundaries of the information systems.',
                'purpose': 'Boundary protection controls network traffic flow and prevents unauthorized access from external threats.',
                'business_impact': 'Without proper boundary protection, organizations are vulnerable to external attacks, data exfiltration, and lateral movement by attackers.',
                'risk_level': 'High'
            },
            'SC.L1-3.13.5': {
                'title': 'SC.L1-3.13.5 - Public Access Point Controls',
                'short_name': 'DMZ/Public Access Separation',
                'description': 'Deny network communications traffic by default and allow network communications traffic by exception.',
                'purpose': 'This control ensures that publicly accessible systems are properly isolated and controlled.',
                'business_impact': 'Improperly secured public access points can provide attackers with entry into internal networks.',
                'risk_level': 'High'
            }
        }
    
    def generate_pdf_report(self, results_list, output_path):
        """Generate enhanced PDF report matching dashboard structure."""
        if not results_list:
            raise ValueError("No results provided for PDF generation")
        
        # Process the results to get dashboard-style data
        dashboard_data = self._process_results_like_dashboard(results_list)
        
        # Create PDF document with proper margins
        doc = SimpleDocTemplate(
            output_path, 
            pagesize=letter,
            topMargin=0.75*inch, 
            bottomMargin=0.75*inch,
            leftMargin=0.75*inch,
            rightMargin=0.75*inch
        )
        
        story = []
        
        # Generate each section
        self._add_header_section(story, dashboard_data)
        self._add_executive_summary(story, dashboard_data)
        self._add_statistics_section(story, dashboard_data)
        self._add_controls_assessment(story, dashboard_data)
        self._add_device_details(story, dashboard_data)
        self._add_remediation_priorities(story, dashboard_data)
        self._add_footer(story)
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _process_results_like_dashboard(self, results_list):
        """Process results exactly like the dashboard does."""
        total_devices = len(results_list)
        compliant_devices = sum(1 for r in results_list if r.get('compliant', False))
        compliance_rate = (compliant_devices / total_devices) * 100 if total_devices > 0 else 0
        
        # Process control statistics (matching dashboard logic)
        controls_data = {}
        for control_id, control_info in self.cmmc_controls.items():
            passed = sum(1 for r in results_list 
                        if r.get('checks', {}).get(control_id, {}).get('passed', False))
            failed = total_devices - passed
            
            # Extract failure reasons
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
                'risk_level': control_info['risk_level'],
                'failure_reasons': failure_reasons
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
        
        return {
            'total_devices': total_devices,
            'compliant_devices': compliant_devices,
            'compliance_rate': compliance_rate,
            'timestamp': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'controls': controls_data,
            'devices': devices_data,
            'remediation_priorities': remediation_priorities,
            'risk_level': self._calculate_overall_risk_level(results_list)
        }
    
    def _extract_control_issues(self, control_id, control_data):
        """Extract specific issues for a control (matching dashboard logic)."""
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
        """Calculate device compliance score (matching dashboard)."""
        checks = result.get('checks', {})
        if not checks:
            return 0
        
        total_controls = len(checks)
        passed_controls = sum(1 for check in checks.values() if check.get('passed', False))
        
        return int((passed_controls / total_controls) * 100)
    
    def _calculate_device_risk_level(self, result):
        """Calculate device risk level (matching dashboard)."""
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
        """Extract all issues for a device (matching dashboard)."""
        issues = []
        checks = result.get('checks', {})
        
        for control_id, control_data in checks.items():
            if not control_data.get('passed', True):
                control_issues = self._extract_control_issues(control_id, control_data)
                issues.extend(control_issues)
        
        return issues
    
    def _generate_remediation_priorities(self, results_list):
        """Generate prioritized remediation recommendations (matching dashboard)."""
        priorities = []
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
                                'risk_level': control_info.get('risk_level', 'Medium')
                            }
                        issue_analysis[issue]['count'] += 1
        
        # Sort by impact and frequency
        sorted_issues = sorted(issue_analysis.items(), 
                             key=lambda x: (
                                 x[1]['risk_level'] == 'High',
                                 x[1]['count'],
                                 x[1]['control_id']
                             ), reverse=True)
        
        for issue, data in sorted_issues[:10]:
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
                'percentage': percentage
            })
        
        return priorities
    
    def _calculate_overall_risk_level(self, results_list):
        """Calculate overall organizational risk level (matching dashboard)."""
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
    
    def _add_header_section(self, story, data):
        """Add header section matching dashboard."""
        # Main title
        title = Paragraph("CMMC 2.0 Level 1 Compliance Report", self.styles['CustomTitle'])
        story.append(title)
        
        # Subtitle
        subtitle = Paragraph("Cybersecurity Maturity Model Certification Assessment Report", self.styles['CustomSubtitle'])
        story.append(subtitle)
        
        # Metadata
        metadata_text = f"Generated on {data['timestamp']}"
        metadata = Paragraph(metadata_text, self.styles['Normal'])
        story.append(metadata)
        
        # Compliance badge
        compliance_rate = data['compliance_rate']
        if compliance_rate >= 95:
            badge_color = colors.HexColor('#10b981')
            badge_text = "EXCELLENT"
        elif compliance_rate >= 85:
            badge_color = colors.HexColor('#10b981')
            badge_text = "GOOD"
        elif compliance_rate >= 70:
            badge_color = colors.HexColor('#f59e0b')
            badge_text = "WARNING"
        else:
            badge_color = colors.HexColor('#ef4444')
            badge_text = "POOR"
        
        compliance_badge = Paragraph(
            f'<font color="{badge_color}"><b>{compliance_rate:.1f}% Compliant - {badge_text}</b></font>',
            self.styles['Normal']
        )
        story.append(compliance_badge)
        story.append(Spacer(1, 0.3*inch))
    
    def _add_executive_summary(self, story, data):
        """Add executive summary section."""
        # Section header
        header = Paragraph("📊 Executive Summary", self.styles['SectionHeader'])
        story.append(header)
        
        # Summary content
        summary_text = f"""
        This report presents the results of a comprehensive CMMC 2.0 Level 1 compliance assessment 
        conducted on {data['total_devices']} network devices. The assessment evaluated compliance 
        against seven critical cybersecurity controls.
        
        <b>Key Findings:</b><br/>
        • Overall compliance rate: {data['compliance_rate']:.1f}%<br/>
        • Compliant devices: {data['compliant_devices']} of {data['total_devices']}<br/>
        • Risk level: {data['risk_level']}<br/>
        • Priority remediation items: {len(data['remediation_priorities'])}
        """
        
        summary = Paragraph(summary_text, self.styles['Normal'])
        story.append(summary)
        story.append(Spacer(1, 0.2*inch))
    
    def _add_statistics_section(self, story, data):
        """Add statistics section matching dashboard stats grid."""
        # Section header
        header = Paragraph("📈 Compliance Statistics", self.styles['SectionHeader'])
        story.append(header)
        
        # Create stats table
        stats_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Devices', str(data['total_devices']), 'Assessed'],
            ['Compliant Devices', str(data['compliant_devices']), 'Passing'],
            ['Non-Compliant Devices', str(data['total_devices'] - data['compliant_devices']), 'Failing'],
            ['Compliance Rate', f"{data['compliance_rate']:.1f}%", data['risk_level']],
            ['Risk Level', data['risk_level'], self._get_risk_status(data['risk_level'])]
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))
    
    def _add_controls_assessment(self, story, data):
        """Add CMMC controls assessment section matching dashboard."""
        # Section header
        header = Paragraph("🛡️ CMMC 2.0 Level 1 Controls Assessment", self.styles['SectionHeader'])
        story.append(header)
        
        for control_id, control_data in data['controls'].items():
            # Control card container
            control_elements = []
            
            # Control title and status
            compliance_rate = control_data['compliance_rate']
            if compliance_rate >= 100:
                status_color = colors.HexColor('#10b981')
                status_text = "COMPLIANT"
            else:
                status_color = colors.HexColor('#ef4444')
                status_text = "NON-COMPLIANT"
            
            title_text = f'<b>{control_data["title"]}</b> - <font color="{status_color}"><b>{status_text}</b></font>'
            control_title = Paragraph(title_text, self.styles['ControlTitle'])
            control_elements.append(control_title)
            
            # Description
            description = Paragraph(f"<b>Description:</b> {control_data['description']}", self.styles['ControlDescription'])
            control_elements.append(description)
            
            # Purpose
            purpose = Paragraph(f"<b>Purpose:</b> {control_data['purpose']}", self.styles['ControlDescription'])
            control_elements.append(purpose)
            
            # Statistics
            stats_text = f"<b>Results:</b> {control_data['passed']} passing, {control_data['failed']} failing ({compliance_rate:.0f}% compliant)"
            stats = Paragraph(stats_text, self.styles['ControlDescription'])
            control_elements.append(stats)
            
            # Business impact
            business_impact = Paragraph(f"<b>Business Impact:</b> {control_data['business_impact']}", self.styles['ControlDescription'])
            control_elements.append(business_impact)
            
            # Common issues if any
            if control_data['failure_reasons']:
                issues_text = "<b>Common Issues:</b><br/>"
                for reason, count in list(control_data['failure_reasons'].items())[:3]:
                    issues_text += f"• {reason} ({count} devices)<br/>"
                issues = Paragraph(issues_text, self.styles['IssueText'])
                control_elements.append(issues)
            
            # Keep control together on page
            control_section = KeepTogether(control_elements)
            story.append(control_section)
            story.append(Spacer(1, 0.15*inch))
    
    def _add_device_details(self, story, data):
        """Add device compliance details section matching dashboard."""
        # Section header
        header = Paragraph("🖥️ Device Compliance Status", self.styles['SectionHeader'])
        story.append(header)
        
        # Create device table
        device_data = [['Device Name', 'Vendor', 'Score', 'Status', 'Risk Level', 'Issues']]
        
        for device in data['devices']:
            status = "COMPLIANT" if device['compliant'] else "NON-COMPLIANT"
            issues_count = len(device['issues'])
            
            device_data.append([
                device['hostname'],
                device['vendor'],
                f"{device['score']}%",
                status,
                device['risk_level'],
                f"{issues_count} issues"
            ])
        
        device_table = Table(device_data, colWidths=[1.2*inch, 1*inch, 0.6*inch, 0.8*inch, 0.8*inch, 0.8*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(device_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Add device issues details
        non_compliant_devices = [d for d in data['devices'] if not d['compliant']]
        if non_compliant_devices:
            issues_header = Paragraph("🚨 Device Issues Details", self.styles['SectionHeader'])
            story.append(issues_header)
            
            for device in non_compliant_devices[:5]:  # Show top 5 non-compliant devices
                device_name = Paragraph(f"<b>{device['hostname']}</b> ({device['vendor']})", self.styles['DeviceName'])
                story.append(device_name)
                
                for issue in device['issues'][:5]:  # Show top 5 issues per device
                    issue_text = f"• {issue}"
                    issue_para = Paragraph(issue_text, self.styles['IssueText'])
                    story.append(issue_para)
                
                if len(device['issues']) > 5:
                    more_issues = Paragraph(f"• ... and {len(device['issues']) - 5} more issues", self.styles['IssueText'])
                    story.append(more_issues)
                
                story.append(Spacer(1, 0.1*inch))
    
    def _add_remediation_priorities(self, story, data):
        """Add remediation priorities section matching dashboard."""
        # Start new page for remediation
        story.append(PageBreak())
        
        # Section header
        header = Paragraph("🔧 Priority Remediation Recommendations", self.styles['SectionHeader'])
        story.append(header)
        
        if not data['remediation_priorities']:
            no_issues = Paragraph("No remediation priorities identified. All devices are compliant!", self.styles['Normal'])
            story.append(no_issues)
            return
        
        for i, priority in enumerate(data['remediation_priorities'], 1):
            # Priority card
            priority_elements = []
            
            # Priority header
            priority_color = self._get_priority_color(priority['priority'])
            priority_text = f'<b>{i}. {priority["issue"]}</b> - <font color="{priority_color}"><b>{priority["priority"]} PRIORITY</b></font>'
            priority_title = Paragraph(priority_text, self.styles['ControlTitle'])
            priority_elements.append(priority_title)
            
            # Priority details
            details_text = f"<b>Control:</b> {priority['control']} ({priority['control_id']})<br/>"
            details_text += f"<b>Impact:</b> {priority['affected_devices']} devices ({priority['percentage']:.1f}%)"
            details = Paragraph(details_text, self.styles['ControlDescription'])
            priority_elements.append(details)
            
            # Remediation guidance
            guidance_text = "<b>Recommended Actions:</b><br/>"
            if priority['priority'] == 'Critical':
                guidance_text += "• Immediate attention required - implement fixes within 24-48 hours<br/>"
                guidance_text += "• Review and update security policies<br/>"
                guidance_text += "• Conduct security awareness training<br/>"
            elif priority['priority'] == 'High':
                guidance_text += "• Address within 1-2 weeks<br/>"
                guidance_text += "• Implement automated monitoring<br/>"
                guidance_text += "• Update configuration baselines<br/>"
            else:
                guidance_text += "• Address during next maintenance window<br/>"
                guidance_text += "• Document configuration standards<br/>"
                guidance_text += "• Regular compliance monitoring<br/>"
            
            guidance = Paragraph(guidance_text, self.styles['RemediationText'])
            priority_elements.append(guidance)
            
            # Keep priority together
            priority_section = KeepTogether(priority_elements)
            story.append(priority_section)
            story.append(Spacer(1, 0.15*inch))
    
    def _add_footer(self, story):
        """Add footer section."""
        story.append(Spacer(1, 0.3*inch))
        
        # Horizontal line
        line = HRFlowable(width="100%", thickness=1, lineCap='round', color=colors.HexColor('#e2e8f0'))
        story.append(line)
        story.append(Spacer(1, 0.1*inch))
        
        # Footer text
        footer_text = "Generated by CMMC 2.0 Compliance Tool - Enhanced PDF Reporter"
        footer = Paragraph(footer_text, self.styles['Normal'])
        story.append(footer)
        
        # Disclaimer
        disclaimer_text = """
        <b>Disclaimer:</b> This report is generated by an automated compliance assessment tool. 
        Results should be reviewed by qualified cybersecurity professionals. This assessment does not 
        guarantee CMMC certification compliance and should not be considered as official certification documentation.
        """
        disclaimer = Paragraph(disclaimer_text, self.styles['ControlDescription'])
        story.append(disclaimer)
    
    def _get_risk_status(self, risk_level):
        """Get risk status description."""
        status_map = {
            'Low': 'Acceptable',
            'Medium': 'Monitor',
            'High': 'Action Required',
            'Critical': 'Immediate Action'
        }
        return status_map.get(risk_level, 'Unknown')
    
    def _get_priority_color(self, priority):
        """Get color for priority level."""
        color_map = {
            'Critical': colors.HexColor('#ef4444'),
            'High': colors.HexColor('#f59e0b'),
            'Medium': colors.HexColor('#3b82f6'),
            'Low': colors.HexColor('#10b981')
        }
        return color_map.get(priority, colors.black)

# Maintain backward compatibility
SimplePDFReporter = EnhancedPDFReporter

def generate_simple_pdf_report(results_list, output_path):
    """Generate PDF report matching dashboard design."""
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "ReportLab is required for PDF generation. "
            "Install with: pip install reportlab"
        )
    
    reporter = EnhancedPDFReporter()
    return reporter.generate_pdf_report(results_list, output_path)

if __name__ == "__main__":
    print("Enhanced PDF Reporter - Use generate_simple_pdf_report() function")