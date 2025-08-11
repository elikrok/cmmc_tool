# enhanced_features/pdf_reporter.py
"""Enhanced PDF reporting with charts and executive summary."""

from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime
import json

class CMMCPDFReporter:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles."""
        styles = {}
        
        # Executive summary style
        styles['ExecutiveTitle'] = ParagraphStyle(
            'ExecutiveTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.darkblue,
            alignment=1  # Center
        )
        
        # Compliance status styles
        styles['CompliancePass'] = ParagraphStyle(
            'CompliancePass',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontName='Helvetica-Bold'
        )
        
        styles['ComplianceFail'] = ParagraphStyle(
            'ComplianceFail',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontName='Helvetica-Bold'
        )
        
        return styles
    
    def generate_compliance_report(self, results_list, output_path):
        """Generate comprehensive PDF report from compliance results."""
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        # Title page
        story.extend(self._create_title_page())
        
        # Executive summary
        story.extend(self._create_executive_summary(results_list))
        
        # Compliance overview chart
        story.extend(self._create_compliance_charts(results_list))
        
        # Detailed findings
        story.extend(self._create_detailed_findings(results_list))
        
        # Recommendations
        story.extend(self._create_recommendations(results_list))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _create_title_page(self):
        """Create report title page."""
        elements = []
        
        # Title
        title = Paragraph("CMMC 2.0 Level 1 Compliance Report", self.custom_styles['ExecutiveTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        report_date = datetime.now().strftime("%B %d, %Y")
        metadata = [
            f"Report Generated: {report_date}",
            "Compliance Framework: CMMC 2.0 Level 1",
            "Assessment Type: Network Device Configuration Review"
        ]
        
        for item in metadata:
            elements.append(Paragraph(item, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        elements.append(Spacer(1, 1*inch))
        return elements
    
    def _create_executive_summary(self, results_list):
        """Create executive summary section."""
        elements = []
        
        # Section title
        elements.append(Paragraph("Executive Summary", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Calculate summary statistics
        total_devices = len(results_list)
        compliant_devices = sum(1 for r in results_list if r.get('compliant', False))
        compliance_rate = (compliant_devices / total_devices * 100) if total_devices > 0 else 0
        
        # Summary paragraph
        summary_text = f"""
        This report presents the results of a CMMC 2.0 Level 1 compliance assessment 
        conducted on {total_devices} network devices. The overall compliance rate is 
        {compliance_rate:.1f}% ({compliant_devices} out of {total_devices} devices).
        
        The assessment evaluated five critical security controls:
        • CM.L1-3.4.1: Baseline Configuration Management
        • AC.L1-3.1.1: Authorized User Control
        • AC.L1-3.1.2: Transaction Limitation
        • SC.L1-3.13.1: Boundary Protection
        • SC.L1-3.13.5: Public Access Point Separation
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_compliance_charts(self, results_list):
        """Create visual compliance charts."""
        elements = []
        
        elements.append(Paragraph("Compliance Overview", self.styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Create pie chart for overall compliance
        chart_data = self._calculate_chart_data(results_list)
        
        # Compliance by control chart
        control_chart = self._create_control_compliance_chart(results_list)
        if control_chart:
            elements.append(control_chart)
        
        elements.append(Spacer(1, 0.5*inch))
        return elements
    
    def _create_detailed_findings(self, results_list):
        """Create detailed findings section."""
        elements = []
        
        elements.append(Paragraph("Detailed Findings", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        for result in results_list:
            elements.extend(self._create_device_section(result))
        
        return elements
    
    def _create_device_section(self, result):
        """Create section for individual device."""
        elements = []
        
        hostname = result.get('hostname', 'Unknown')
        compliant = result.get('compliant', False)
        
        # Device header
        status_style = self.custom_styles['CompliancePass'] if compliant else self.custom_styles['ComplianceFail']
        status_text = "COMPLIANT" if compliant else "NON-COMPLIANT"
        
        elements.append(Paragraph(f"Device: {hostname}", self.styles['Heading2']))
        elements.append(Paragraph(f"Status: {status_text}", status_style))
        elements.append(Spacer(1, 0.1*inch))
        
        # Control results table
        if 'checks' in result:
            table_data = [['Control', 'Status', 'Details']]
            
            for control, data in result['checks'].items():
                status = "PASS" if data.get('passed', False) else "FAIL"
                details = self._format_control_details(control, data)
                table_data.append([control, status, details])
            
            table = Table(table_data, colWidths=[1.5*inch, 1*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(table)
        
        elements.append(Spacer(1, 0.3*inch))
        return elements
    
    def _format_control_details(self, control, data):
        """Format control-specific details."""
        if control == "AC.L1-3.1.1":
            aaa = "Yes" if data.get('aaa_configured') else "No"
            servers = len(data.get('tacacs_servers', []))
            return f"AAA: {aaa}, TACACS Servers: {servers}"
        elif control == "AC.L1-3.1.2":
            enable_secret = "Yes" if data.get('enable_secret_present') else "No"
            no_telnet = "Yes" if data.get('no_telnet') else "No"
            return f"Enable Secret: {enable_secret}, No Telnet: {no_telnet}"
        elif control == "SC.L1-3.13.1":
            ssh_mgmt = "Yes" if data.get('ssh_mgmt') else "No"
            acls = "Yes" if data.get('acls_present_and_applied') else "No"
            return f"SSH Management: {ssh_mgmt}, ACLs Applied: {acls}"
        elif control == "SC.L1-3.13.5":
            dmz_issues = len(data.get('dmz_interfaces_without_acl', []))
            return f"DMZ Interfaces Missing ACL: {dmz_issues}"
        else:
            return "Configuration baseline check"
    
    def _create_recommendations(self, results_list):
        """Create recommendations section."""
        elements = []
        
        elements.append(Paragraph("Recommendations", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Analyze common issues and generate recommendations
        recommendations = self._analyze_common_issues(results_list)
        
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _analyze_common_issues(self, results_list):
        """Analyze results and generate recommendations."""
        recommendations = []
        
        # Count common issues
        issues = {
            'aaa_missing': 0,
            'enable_secret_missing': 0,
            'telnet_enabled': 0,
            'ssh_missing': 0,
            'acl_missing': 0,
            'dmz_unprotected': 0
        }
        
        for result in results_list:
            checks = result.get('checks', {})
            
            # AC.L1-3.1.1 issues
            if not checks.get('AC.L1-3.1.1', {}).get('aaa_configured', True):
                issues['aaa_missing'] += 1
            
            # AC.L1-3.1.2 issues
            ac_312 = checks.get('AC.L1-3.1.2', {})
            if not ac_312.get('enable_secret_present', True):
                issues['enable_secret_missing'] += 1
            if not ac_312.get('no_telnet', True):
                issues['telnet_enabled'] += 1
            
            # SC.L1-3.13.1 issues
            sc_1331 = checks.get('SC.L1-3.13.1', {})
            if not sc_1331.get('ssh_mgmt', True):
                issues['ssh_missing'] += 1
            if not sc_1331.get('acls_present_and_applied', True):
                issues['acl_missing'] += 1
            
            # SC.L1-3.13.5 issues
            if checks.get('SC.L1-3.13.5', {}).get('dmz_interfaces_without_acl', []):
                issues['dmz_unprotected'] += 1
        
        # Generate recommendations based on issues
        if issues['aaa_missing'] > 0:
            recommendations.append(
                f"Implement AAA authentication on {issues['aaa_missing']} devices. "
                "Configure TACACS+ servers with local fallback for centralized user management."
            )
        
        if issues['enable_secret_missing'] > 0:
            recommendations.append(
                f"Configure enable secret on {issues['enable_secret_missing']} devices "
                "to protect privileged access mode."
            )
        
        if issues['telnet_enabled'] > 0:
            recommendations.append(
                f"Disable Telnet on {issues['telnet_enabled']} devices. "
                "Use SSH exclusively for secure remote management."
            )
        
        if issues['acl_missing'] > 0:
            recommendations.append(
                f"Implement and apply access control lists on {issues['acl_missing']} devices "
                "to control network traffic and management access."
            )
        
        if issues['dmz_unprotected'] > 0:
            recommendations.append(
                f"Apply ACLs to DMZ interfaces on {issues['dmz_unprotected']} devices "
                "to properly separate public-facing services."
            )
        
        if not recommendations:
            recommendations.append("All devices meet CMMC 2.0 Level 1 requirements. Continue monitoring and maintain current security posture.")
        
        return recommendations
    
    def _calculate_chart_data(self, results_list):
        """Calculate data for charts."""
        total = len(results_list)
        compliant = sum(1 for r in results_list if r.get('compliant', False))
        non_compliant = total - compliant
        
        return {
            'compliant': compliant,
            'non_compliant': non_compliant,
            'total': total,
            'compliance_rate': (compliant / total * 100) if total > 0 else 0
        }
    
    def _create_control_compliance_chart(self, results_list):
        """Create bar chart showing compliance by control."""
        controls = ['CM.L1-3.4.1', 'AC.L1-3.1.1', 'AC.L1-3.1.2', 'SC.L1-3.13.1', 'SC.L1-3.13.5']
        control_stats = {}
        
        for control in controls:
            passed = sum(1 for r in results_list 
                        if r.get('checks', {}).get(control, {}).get('passed', False))
            control_stats[control] = (passed / len(results_list) * 100) if results_list else 0
        
        # Create matplotlib chart and convert to ReportLab image
        fig, ax = plt.subplots(figsize=(8, 4))
        bars = ax.bar(range(len(controls)), list(control_stats.values()), 
                     color=['green' if v >= 100 else 'orange' if v >= 80 else 'red' 
                           for v in control_stats.values()])
        
        ax.set_xlabel('CMMC Controls')
        ax.set_ylabel('Compliance Percentage')
        ax.set_title('Compliance by Control')
        ax.set_xticks(range(len(controls)))
        ax.set_xticklabels([c.split('-')[0] for c in controls], rotation=45)
        ax.set_ylim(0, 100)
        
        # Add percentage labels on bars
        for bar, value in zip(bars, control_stats.values()):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 1, f'{value:.1f}%',
                   ha='center', va='bottom')
        
        plt.tight_layout()
        
        # Convert to image for ReportLab
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        # Create ReportLab image
        img = Image(img_buffer, width=6*inch, height=3*inch)
        return img