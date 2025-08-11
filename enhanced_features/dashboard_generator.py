# enhanced_features/dashboard_generator.py
"""Generate HTML dashboard for compliance tracking."""

import json
from datetime import datetime, timedelta
import os
from pathlib import Path

class CMMCDashboard:
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        
    def generate_dashboard(self, results_list, output_path="dashboard.html"):
        """Generate interactive HTML dashboard."""
        
        # Prepare data for dashboard
        dashboard_data = self._prepare_dashboard_data(results_list)
        
        # Generate HTML
        html_content = self._create_html_dashboard(dashboard_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _prepare_dashboard_data(self, results_list):
        """Prepare data structure for dashboard."""
        data = {
            'timestamp': datetime.now().isoformat(),
            'summary': self._calculate_summary_stats(results_list),
            'devices': self._format_device_data(results_list),
            'controls': self._calculate_control_stats(results_list),
            'trends': self._generate_trend_data(results_list)
        }
        return data
    
    def _calculate_summary_stats(self, results_list):
        """Calculate high-level summary statistics."""
        total_devices = len(results_list)
        compliant_devices = sum(1 for r in results_list if r.get('compliant', False))
        
        # Risk calculation
        critical_failures = 0
        for result in results_list:
            checks = result.get('checks', {})
            # Count critical security failures
            if not checks.get('AC.L1-3.1.1', {}).get('passed', True):
                critical_failures += 1
            if not checks.get('SC.L1-3.13.1', {}).get('passed', True):
                critical_failures += 1
        
        risk_level = "Low" if critical_failures == 0 else "Medium" if critical_failures <= 2 else "High"
        
        return {
            'total_devices': total_devices,
            'compliant_devices': compliant_devices,
            'compliance_rate': (compliant_devices / total_devices * 100) if total_devices > 0 else 0,
            'critical_failures': critical_failures,
            'risk_level': risk_level
        }
    
    def _format_device_data(self, results_list):
        """Format device data for dashboard table."""
        devices = []
        for result in results_list:
            device = {
                'hostname': result.get('hostname', 'Unknown'),
                'compliant': result.get('compliant', False),
                'controls_passed': sum(1 for check in result.get('checks', {}).values() 
                                     if check.get('passed', False)),
                'total_controls': len(result.get('checks', {})),
                'issues': self._identify_device_issues(result)
            }
            devices.append(device)
        return devices
    
    def _identify_device_issues(self, result):
        """Identify specific issues for a device."""
        issues = []
        checks = result.get('checks', {})
        
        for control, data in checks.items():
            if not data.get('passed', True):
                if control == 'AC.L1-3.1.1':
                    if not data.get('aaa_configured'):
                        issues.append("AAA not configured")
                    if not data.get('tacacs_servers'):
                        issues.append("No TACACS servers defined")
                elif control == 'AC.L1-3.1.2':
                    if not data.get('enable_secret_present'):
                        issues.append("No enable secret")
                    if not data.get('no_telnet'):
                        issues.append("Telnet enabled")
                elif control == 'SC.L1-3.13.1':
                    if not data.get('ssh_mgmt'):
                        issues.append("SSH management not configured")
                    if not data.get('acls_present_and_applied'):
                        issues.append("ACLs missing or not applied")
                elif control == 'SC.L1-3.13.5':
                    dmz_issues = data.get('dmz_interfaces_without_acl', [])
                    if dmz_issues:
                        issues.append(f"DMZ interfaces without ACL: {len(dmz_issues)}")
        
        return issues
    
    def _calculate_control_stats(self, results_list):
        """Calculate statistics for each control."""
        controls = ['CM.L1-3.4.1', 'AC.L1-3.1.1', 'AC.L1-3.1.2', 'SC.L1-3.13.1', 'SC.L1-3.13.5']
        control_stats = {}
        
        for control in controls:
            passed = sum(1 for r in results_list 
                        if r.get('checks', {}).get(control, {}).get('passed', False))
            failed = len(results_list) - passed
            
            control_stats[control] = {
                'passed': passed,
                'failed': failed,
                'compliance_rate': (passed / len(results_list) * 100) if results_list else 0,
                'description': self._get_control_description(control)
            }
        
        return control_stats
    
    def _get_control_description(self, control):
        """Get human-readable description for control."""
        descriptions = {
            'CM.L1-3.4.1': 'Baseline Configuration Management',
            'AC.L1-3.1.1': 'Authorized User Control',
            'AC.L1-3.1.2': 'Transaction Limitation',
            'SC.L1-3.13.1': 'Boundary Protection',
            'SC.L1-3.13.5': 'Public Access Point Separation'
        }
        return descriptions.get(control, control)
    
    def _generate_trend_data(self, results_list):
        """Generate mock trend data (in real implementation, this would use historical data)."""
        # For demo purposes, generate some sample trend data
        dates = [(datetime.now() - timedelta(days=x)).strftime('%Y-%m-%d') for x in range(30, 0, -1)]
        
        # Simulate compliance trend
        current_rate = self._calculate_summary_stats(results_list)['compliance_rate']
        base_rate = max(0, current_rate - 20)
        
        trend_data = []
        for i, date in enumerate(dates):
            # Simulate gradual improvement
            rate = base_rate + (current_rate - base_rate) * (i / len(dates))
            trend_data.append({'date': date, 'compliance_rate': round(rate, 1)})
        
        return trend_data
    
    def _create_html_dashboard(self, data):
        """Create the HTML dashboard content."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMMC 2.0 Compliance Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }}
        
        .compliant {{ color: #27ae60; }}
        .non-compliant {{ color: #e74c3c; }}
        .warning {{ color: #f39c12; }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        
        .chart-container {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .devices-table {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .table-header {{
            background: #34495e;
            color: white;
            padding: 1rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        
        .status-badge {{
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        
        .badge-compliant {{
            background: #d4edda;
            color: #155724;
        }}
        
        .badge-non-compliant {{
            background: #f8d7da;
            color: #721c24;
        }}
        
        .issues-list {{
            max-width: 300px;
        }}
        
        .issue-item {{
            background: #fff3cd;
            color: #856404;
            padding: 0.2rem 0.5rem;
            margin: 0.2rem 0;
            border-radius: 4px;
            font-size: 0.8rem;
        }}
        
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CMMC 2.0 Compliance Dashboard</h1>
        <p>Last Updated: {datetime.fromisoformat(data['timestamp']).strftime('%B %d, %Y at %I:%M %p')}</p>
    </div>
    
    <div class="container">
        <!-- Summary Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number compliant">{data['summary']['compliant_devices']}</div>
                <div>Compliant Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number non-compliant">{data['summary']['total_devices'] - data['summary']['compliant_devices']}</div>
                <div>Non-Compliant Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number {'compliant' if data['summary']['compliance_rate'] >= 80 else 'warning' if data['summary']['compliance_rate'] >= 60 else 'non-compliant'}">{data['summary']['compliance_rate']:.1f}%</div>
                <div>Overall Compliance Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-number {'compliant' if data['summary']['risk_level'] == 'Low' else 'warning' if data['summary']['risk_level'] == 'Medium' else 'non-compliant'}">{data['summary']['risk_level']}</div>
                <div>Risk Level</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Compliance by Control</h3>
                <canvas id="controlChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Compliance Trend</h3>
                <canvas id="trendChart"></canvas>
            </div>
        </div>
        
        <!-- Device Details Table -->
        <div class="devices-table">
            <div class="table-header">
                <h3>Device Compliance Details</h3>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Device</th>
                        <th>Status</th>
                        <th>Controls Passed</th>
                        <th>Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_device_rows(data['devices'])}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Control compliance chart
        const controlCtx = document.getElementById('controlChart').getContext('2d');
        new Chart(controlCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps([self._get_control_description(control) for control in data['controls'].keys()])},
                datasets: [{{
                    label: 'Compliance Rate (%)',
                    data: {json.dumps([data['controls'][control]['compliance_rate'] for control in data['controls'].keys()])},
                    backgroundColor: {json.dumps([
                        '#27ae60' if data['controls'][control]['compliance_rate'] >= 100 
                        else '#f39c12' if data['controls'][control]['compliance_rate'] >= 80 
                        else '#e74c3c' 
                        for control in data['controls'].keys()
                    ])},
                    borderRadius: 5
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{
                            callback: function(value) {{
                                return value + '%';
                            }}
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
        
        // Trend chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: {json.dumps([item['date'] for item in data['trends']])},
                datasets: [{{
                    label: 'Compliance Rate',
                    data: {json.dumps([item['compliance_rate'] for item in data['trends']])},
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{
                            callback: function(value) {{
                                return value + '%';
                            }}
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
        """
    
    def _generate_device_rows(self, devices):
        """Generate HTML table rows for devices."""
        rows = []
        for device in devices:
            status_class = 'badge-compliant' if device['compliant'] else 'badge-non-compliant'
            status_text = 'Compliant' if device['compliant'] else 'Non-Compliant'
            
            issues_html = ''
            for issue in device['issues'][:3]:  # Show max 3 issues
                issues_html += f'<div class="issue-item">{issue}</div>'
            if len(device['issues']) > 3:
                issues_html += f'<div class="issue-item">+{len(device['issues']) - 3} more...</div>'
            
            row = f"""
                <tr>
                    <td>{device['hostname']}</td>
                    <td><span class="status-badge {status_class}">{status_text}</span></td>
                    <td>{device['controls_passed']}/{device['total_controls']}</td>
                    <td><div class="issues-list">{issues_html}</div></td>
                </tr>
            """
            rows.append(row)
        
        return ''.join(rows)