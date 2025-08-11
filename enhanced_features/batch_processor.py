# enhanced_features/batch_processor.py
"""Batch processing for multiple device configurations."""

import concurrent.futures
import os
from pathlib import Path
import json
import threading
from datetime import datetime

class CMMCBatchProcessor:
    def __init__(self, max_workers=4):
        self.max_workers = max_workers
        self.progress_callback = None
        self.results = []
        self.lock = threading.Lock()
    
    def process_directory(self, current_dir, baseline_dir, output_dir, 
                         skip_connectivity=True, progress_callback=None):
        """Process all config files in directories with parallel processing."""
        
        self.progress_callback = progress_callback
        self.results = []
        
        # Find matching config files
        current_path = Path(current_dir)
        baseline_path = Path(baseline_dir)
        output_path = Path(output_dir)
        
        config_files = list(current_path.glob("*.cfg"))
        if not config_files:
            raise ValueError(f"No .cfg files found in {current_dir}")
        
        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Process files in parallel
        total_files = len(config_files)
        processed_files = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {}
            for config_file in config_files:
                baseline_file = baseline_path / config_file.name
                if baseline_file.exists():
                    future = executor.submit(
                        self._process_single_file,
                        str(config_file),
                        str(baseline_file),
                        skip_connectivity
                    )
                    future_to_file[future] = config_file.name
            
            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_file):
                filename = future_to_file[future]
                try:
                    result = future.result()
                    with self.lock:
                        self.results.append(result)
                        processed_files += 1
                    
                    # Update progress
                    if self.progress_callback:
                        progress = (processed_files / total_files) * 100
                        self.progress_callback(progress, filename)
                
                except Exception as e:
                    print(f"Error processing {filename}: {e}")
                    # Add error result
                    with self.lock:
                        self.results.append({
                            'hostname': filename.replace('.cfg', ''),
                            'compliant': False,
                            'error': str(e),
                            'checks': {}
                        })
                        processed_files += 1
        
        # Generate consolidated reports
        self._generate_consolidated_reports(output_path)
        
        return {
            'total_processed': len(self.results),
            'compliant_devices': sum(1 for r in self.results if r.get('compliant', False)),
            'results': self.results,
            'output_directory': str(output_path)
        }
    
    def _process_single_file(self, current_file, baseline_file, skip_connectivity):
        """Process a single configuration file."""
        from scanner.config_checker import check_config_compliance
        
        result = check_config_compliance(current_file, baseline_file, skip_connectivity)
        result['file_path'] = current_file
        result['timestamp'] = datetime.now().isoformat()
        
        return result
    
    def _generate_consolidated_reports(self, output_path):
        """Generate consolidated reports from all results."""
        from reporter.simple_report import write_result
        
        # Generate individual reports
        for result in self.results:
            write_result(result, str(output_path))
        
        # Generate summary report
        self._generate_summary_report(output_path)
        
        # Generate JSON export
        self._generate_json_export(output_path)
    
    def _generate_summary_report(self, output_path):
        """Generate executive summary report."""
        summary_path = output_path / "executive_summary.txt"
        
        total_devices = len(self.results)
        compliant_devices = sum(1 for r in self.results if r.get('compliant', False))
        compliance_rate = (compliant_devices / total_devices * 100) if total_devices > 0 else 0
        
        # Analyze control-specific compliance
        controls = ['CM.L1-3.4.1', 'AC.L1-3.1.1', 'AC.L1-3.1.2', 'SC.L1-3.13.1', 'SC.L1-3.13.5']
        control_stats = {}
        
        for control in controls:
            passed = sum(1 for r in self.results 
                        if r.get('checks', {}).get(control, {}).get('passed', False))
            control_stats[control] = {
                'passed': passed,
                'failed': total_devices - passed,
                'rate': (passed / total_devices * 100) if total_devices > 0 else 0
            }
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("CMMC 2.0 Level 1 Compliance - Executive Summary\n")
            f.write("=" * 55 + "\n\n")
            f.write(f"Report Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}\n")
            f.write(f"Total Devices Assessed: {total_devices}\n")
            f.write(f"Compliant Devices: {compliant_devices}\n")
            f.write(f"Non-Compliant Devices: {total_devices - compliant_devices}\n")
            f.write(f"Overall Compliance Rate: {compliance_rate:.1f}%\n\n")
            
            # Risk assessment
            risk_level = "Low" if compliance_rate >= 90 else "Medium" if compliance_rate >= 70 else "High"
            f.write(f"Risk Level: {risk_level}\n\n")
            
            # Control-specific results
            f.write("Control-Specific Compliance Rates:\n")
            f.write("-" * 40 + "\n")
            for control, stats in control_stats.items():
                f.write(f"{control}: {stats['rate']:.1f}% ({stats['passed']}/{total_devices})\n")
            
            f.write("\n\nTop Issues Found:\n")
            f.write("-" * 20 + "\n")
            
            # Identify common issues
            issues = self._analyze_common_issues()
            for i, (issue, count) in enumerate(issues[:5], 1):
                f.write(f"{i}. {issue} ({count} devices)\n")
            
            f.write("\n\nRecommendations:\n")
            f.write("-" * 15 + "\n")
            recommendations = self._generate_recommendations()
            for i, rec in enumerate(recommendations[:5], 1):
                f.write(f"{i}. {rec}\n")
    
    def _analyze_common_issues(self):
        """Analyze and return most common issues across all devices."""
        issue_counts = {}
        
        for result in self.results:
            checks = result.get('checks', {})
            
            # AC.L1-3.1.1 issues
            ac_3111 = checks.get('AC.L1-3.1.1', {})
            if not ac_3111.get('aaa_configured', True):
                issue_counts['AAA authentication not configured'] = issue_counts.get('AAA authentication not configured', 0) + 1
            if not ac_3111.get('tacacs_servers'):
                issue_counts['No TACACS servers defined'] = issue_counts.get('No TACACS servers defined', 0) + 1
            
            # AC.L1-3.1.2 issues
            ac_3112 = checks.get('AC.L1-3.1.2', {})
            if not ac_3112.get('enable_secret_present', True):
                issue_counts['Enable secret not configured'] = issue_counts.get('Enable secret not configured', 0) + 1
            if not ac_3112.get('no_telnet', True):
                issue_counts['Telnet access enabled'] = issue_counts.get('Telnet access enabled', 0) + 1
            
            # SC.L1-3.13.1 issues
            sc_1331 = checks.get('SC.L1-3.13.1', {})
            if not sc_1331.get('ssh_mgmt', True):
                issue_counts['SSH management not configured'] = issue_counts.get('SSH management not configured', 0) + 1
            if not sc_1331.get('acls_present_and_applied', True):
                issue_counts['Access control lists missing'] = issue_counts.get('Access control lists missing', 0) + 1
            
            # SC.L1-3.13.5 issues
            sc_1335 = checks.get('SC.L1-3.13.5', {})
            if sc_1335.get('dmz_interfaces_without_acl', []):
                issue_counts['DMZ interfaces without ACL protection'] = issue_counts.get('DMZ interfaces without ACL protection', 0) + 1
        
        # Sort by frequency
        return sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)
    
    def _generate_recommendations(self):
        """Generate prioritized recommendations based on analysis."""
        recommendations = []
        issues = self._analyze_common_issues()
        
        for issue, count in issues[:3]:  # Top 3 issues
            if 'AAA authentication' in issue:
                recommendations.append(
                    "Implement centralized AAA authentication with TACACS+ servers "
                    "and local fallback on all network devices"
                )
            elif 'Enable secret' in issue:
                recommendations.append(
                    "Configure enable secret on all devices to protect privileged access mode"
                )
            elif 'Telnet access' in issue:
                recommendations.append(
                    "Disable Telnet and use SSH exclusively for secure remote management"
                )
            elif 'SSH management' in issue:
                recommendations.append(
                    "Configure SSH-only management access and disable insecure protocols"
                )
            elif 'Access control lists' in issue:
                recommendations.append(
                    "Implement and apply access control lists for network segmentation and security"
                )
            elif 'DMZ interfaces' in issue:
                recommendations.append(
                    "Apply access control lists to DMZ interfaces to control public access"
                )
        
        # Add general recommendations
        if len(recommendations) < 5:
            recommendations.extend([
                "Establish regular compliance monitoring and automated checking",
                "Implement configuration backup and change management processes",
                "Conduct regular security assessments and penetration testing",
                "Provide security training for network administration staff",
                "Document all security configurations and maintain current baselines"
            ])
        
        return recommendations[:5]
    
    def _generate_json_export(self, output_path):
        """Generate JSON export of all results."""
        json_path = output_path / "compliance_results.json"
        
        export_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'compliance_framework': 'CMMC 2.0 Level 1',
                'total_devices': len(self.results)
            },
            'summary_statistics': {
                'total_devices': len(self.results),
                'compliant_devices': sum(1 for r in self.results if r.get('compliant', False)),
                'compliance_rate': (sum(1 for r in self.results if r.get('compliant', False)) / len(self.results) * 100) if self.results else 0
            },
            'device_results': self.results,
            'common_issues': dict(self._analyze_common_issues()),
            'recommendations': self._generate_recommendations()
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)