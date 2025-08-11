# enhanced_features/cli_interface.py
"""Command-line interface for the CMMC tool."""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

class CMMCCommandLine:
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self):
        """Create command-line argument parser."""
        parser = argparse.ArgumentParser(
            description='CMMC 2.0 Level 1 Compliance Checker',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic compliance check
  python -m cmmc_tool check --current ./configs --baseline ./baseline --output ./results
  
  # Generate PDF and dashboard
  python -m cmmc_tool check --current ./configs --baseline ./baseline --pdf --dashboard
  
  # Batch process with parallel workers
  python -m cmmc_tool batch --current ./configs --baseline ./baseline --workers 8
  
  # Generate remediation plan
  python -m cmmc_tool remediate --results ./results/compliance_results.json --output ./remediation
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Check command
        check_parser = subparsers.add_parser('check', help='Run compliance check')
        check_parser.add_argument('--current', '-c', required=True, 
                                help='Current configuration directory')
        check_parser.add_argument('--baseline', '-b', required=True,
                                help='Baseline configuration directory')
        check_parser.add_argument('--output', '-o', default='output',
                                help='Output directory (default: output)')
        check_parser.add_argument('--skip-connectivity', action='store_true',
                                help='Skip TACACS connectivity tests')
        check_parser.add_argument('--pdf', action='store_true',
                                help='Generate PDF report')
        check_parser.add_argument('--dashboard', action='store_true',
                                help='Generate HTML dashboard')
        check_parser.add_argument('--json', action='store_true',
                                help='Generate JSON export')
        check_parser.add_argument('--quiet', '-q', action='store_true',
                                help='Suppress progress output')
        
        # Batch command
        batch_parser = subparsers.add_parser('batch', help='Batch process multiple directories')
        batch_parser.add_argument('--current', '-c', required=True,
                                help='Current configuration directory')
        batch_parser.add_argument('--baseline', '-b', required=True,
                                help='Baseline configuration directory')
        batch_parser.add_argument('--output', '-o', default='output',
                                help='Output directory')
        batch_parser.add_argument('--workers', '-w', type=int, default=4,
                                help='Number of parallel workers (default: 4)')
        batch_parser.add_argument('--skip-connectivity', action='store_true',
                                help='Skip TACACS connectivity tests')
        
        # Remediate command
        remediate_parser = subparsers.add_parser('remediate', help='Generate remediation plan')
        remediate_parser.add_argument('--results', '-r', required=True,
                                    help='Compliance results JSON file')
        remediate_parser.add_argument('--output', '-o', default='remediation',
                                    help='Remediation output directory')
        remediate_parser.add_argument('--format', choices=['text', 'json', 'both'], default='both',
                                    help='Output format (default: both)')
        
        # Validate command
        validate_parser = subparsers.add_parser('validate', help='Validate single configuration')
        validate_parser.add_argument('--config', '-c', required=True,
                                   help='Configuration file to validate')
        validate_parser.add_argument('--type', choices=['auto', 'cisco_router', 'cisco_switch', 'arista_switch'],
                                   default='auto', help='Device type (default: auto-detect)')
        
        # Report command
        report_parser = subparsers.add_parser('report', help='Generate reports from existing results')
        report_parser.add_argument('--results', '-r', required=True,
                                 help='Compliance results directory or JSON file')
        report_parser.add_argument('--output', '-o', default='reports',
                                 help='Report output directory')
        report_parser.add_argument('--pdf', action='store_true', help='Generate PDF report')
        report_parser.add_argument('--dashboard', action='store_true', help='Generate HTML dashboard')
        
        return parser
    
    def run(self, args=None):
        """Run the command-line interface."""
        if args is None:
            args = sys.argv[1:]
        
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return 1
        
        try:
            if parsed_args.command == 'check':
                return self._run_check(parsed_args)
            elif parsed_args.command == 'batch':
                return self._run_batch(parsed_args)
            elif parsed_args.command == 'remediate':
                return self._run_remediate(parsed_args)
            elif parsed_args.command == 'validate':
                return self._run_validate(parsed_args)
            elif parsed_args.command == 'report':
                return self._run_report(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}")
                return 1
        
        except Exception as e:
            print(f"Error: {e}")
            return 1
    
    def _run_check(self, args):
        """Run compliance check command."""
        from scanner.config_checker import check_config_compliance
        from reporter.simple_report import write_result
        
        current_path = Path(args.current)
        baseline_path = Path(args.baseline)
        output_path = Path(args.output)
        
        if not current_path.exists():
            raise ValueError(f"Current directory does not exist: {current_path}")
        if not baseline_path.exists():
            raise ValueError(f"Baseline directory does not exist: {baseline_path}")
        
        # Find config files
        config_files = list(current_path.glob("*.cfg"))
        if not config_files:
            raise ValueError(f"No .cfg files found in {current_path}")
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        results = []
        total_files = len(config_files)
        
        for i, config_file in enumerate(config_files, 1):
            baseline_file = baseline_path / config_file.name
            if not baseline_file.exists():
                if not args.quiet:
                    print(f"Skipping {config_file.name} (no baseline found)")
                continue
            
            if not args.quiet:
                print(f"Processing {config_file.name} ({i}/{total_files})...")
            
            # Run compliance check
            result = check_config_compliance(
                str(config_file), 
                str(baseline_file), 
                skip_connectivity=args.skip_connectivity
            )
            result['file_path'] = str(config_file)
            result['timestamp'] = datetime.now().isoformat()
            
            # Write individual result
            write_result(result, str(output_path))
            results.append(result)
        
        # Generate additional reports
        if args.json:
            self._generate_json_export(results, output_path)
        
        if args.pdf:
            self._generate_pdf_report(results, output_path)
        
        if args.dashboard:
            self._generate_dashboard(results, output_path)
        
        # Print summary
        compliant = sum(1 for r in results if r.get('compliant', False))
        print(f"\nCompliance check complete!")
        print(f"Devices processed: {len(results)}")
        print(f"Compliant devices: {compliant}")
        print(f"Compliance rate: {(compliant/len(results)*100):.1f}%")
        print(f"Results saved to: {output_path}")
        
        return 0
    
    def _run_batch(self, args):
        """Run batch processing command."""
        from enhanced_features.batch_processor import CMMCBatchProcessor
        
        processor = CMMCBatchProcessor(max_workers=args.workers)
        
        def progress_callback(percentage, filename):
            if not args.quiet:
                print(f"Progress: {percentage:.1f}% - {filename}")
        
        results = processor.process_directory(
            current_dir=args.current,
            baseline_dir=args.baseline,
            output_dir=args.output,
            skip_connectivity=args.skip_connectivity,
            progress_callback=progress_callback if not args.quiet else None
        )
        
        print(f"\nBatch processing complete!")
        print(f"Devices processed: {results['total_processed']}")
        print(f"Compliant devices: {results['compliant_devices']}")
        print(f"Results saved to: {results['output_directory']}")
        
        return 0
    
    def _run_remediate(self, args):
        """Run remediation command."""
        from enhanced_features.remediation_engine import CMMCRemediationEngine
        
        results_path = Path(args.results)
        if not results_path.exists():
            raise ValueError(f"Results file does not exist: {results_path}")
        
        # Load results
        with open(results_path, 'r') as f:
            data = json.load(f)
        
        results = data.get('device_results', [])
        if not results:
            raise ValueError("No device results found in JSON file")
        
        # Generate remediation plan
        engine = CMMCRemediationEngine()
        plan = engine.generate_remediation_plan(results)
        
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export scripts
        script_path = engine.export_remediation_scripts(plan, output_path)
        
        print(f"Remediation plan generated!")
        print(f"Devices needing remediation: {plan['summary']['devices_needing_remediation']}")
        print(f"Total commands: {plan['summary']['total_commands']}")
        print(f"Estimated time: {plan['summary']['estimated_time_minutes']} minutes")
        print(f"Scripts saved to: {output_path}")
        print(f"Master script: {script_path}")
        
        return 0
    
    def _run_validate(self, args):
        """Run validation command."""
        from enhanced_features.config_validator import CMMCConfigValidator
        
        config_path = Path(args.config)
        if not config_path.exists():
            raise ValueError(f"Configuration file does not exist: {config_path}")
        
        validator = CMMCConfigValidator()
        results = validator.validate_configuration(str(config_path), args.type)
        
        print(f"Configuration Validation Results for {config_path.name}")
        print("=" * 50)
        print(f"Device Type: {results['device_type']}")
        print(f"Security Score: {results['security_score']}/100")
        
        if results['vulnerabilities']:
            print(f"\nVulnerabilities Found ({len(results['vulnerabilities'])}):")
            for vuln in results['vulnerabilities']:
                print(f"  • {vuln}")
        
        if results['recommendations']:
            print(f"\nRecommendations ({len(results['recommendations'])}):")
            for rec in results['recommendations']:
                print(f"  • {rec}")
        
        return 0
    
    def _run_report(self, args):
        """Run report generation command."""
        results_path = Path(args.results)
        
        if results_path.is_file() and results_path.suffix == '.json':
            # Load from JSON file
            with open(results_path, 'r') as f:
                data = json.load(f)
            results = data.get('device_results', [])
        elif results_path.is_dir():
            # Load from CSV files in directory
            results = self._load_results_from_csv(results_path)
        else:
            raise ValueError(f"Invalid results path: {results_path}")
        
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if args.pdf:
            self._generate_pdf_report(results, output_path)
        
        if args.dashboard:
            self._generate_dashboard(results, output_path)
        
        print(f"Reports generated in: {output_path}")
        return 0
    
    def _generate_json_export(self, results, output_path):
        """Generate JSON export."""
        json_path = output_path / "compliance_results.json"
        
        export_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'compliance_framework': 'CMMC 2.0 Level 1'
            },
            'device_results': results
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def _generate_pdf_report(self, results, output_path):
        """Generate PDF report."""
        try:
            from enhanced_features.pdf_reporter import CMMCPDFReporter
            reporter = CMMCPDFReporter()
            pdf_path = output_path / "compliance_report.pdf"
            reporter.generate_compliance_report(results, str(pdf_path))
            print(f"PDF report generated: {pdf_path}")
        except ImportError:
            print("PDF generation requires reportlab package: pip install reportlab")
    
    def _generate_dashboard(self, results, output_path):
        """Generate HTML dashboard."""
        from enhanced_features.dashboard_generator import CMMCDashboard
        dashboard = CMMCDashboard()
        html_path = output_path / "dashboard.html"
        dashboard.generate_dashboard(results, str(html_path))
        print(f"Dashboard generated: {html_path}")
    
    def _load_results_from_csv(self, results_dir):
        """Load results from CSV files (simplified implementation)."""
        # This would need to be implemented to parse CSV files back to result format
        csv_files = list(results_dir.glob("*.csv"))
        if not csv_files:
            raise ValueError(f"No CSV files found in {results_dir}")
        
        # For now, return empty list - full implementation would parse CSV
        print("Loading from CSV not fully implemented yet")
        return []


if __name__ == "__main__":
    cli = CMMCCommandLine()
    sys.exit(cli.run())