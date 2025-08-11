# demo_enhanced_features.py
"""Demo script to showcase all the enhanced CMMC tool features."""

import json
import sys
from pathlib import Path
from datetime import datetime

def demo_basic_compliance_check():
    """Demo the basic compliance check functionality."""
    print("🔍 Demo 1: Basic Compliance Check")
    print("-" * 40)
    
    try:
        from scanner.config_checker import check_config_compliance
        from reporter.simple_report import write_result
        
        # Check if mock environment exists
        mock_dir = Path("mock_configs")
        if not mock_dir.exists():
            print("❌ Mock environment not found. Run setup_mock_environment.py first.")
            return False
        
        current_dir = mock_dir / "current"
        output_dir = Path("demo_output")
        output_dir.mkdir(exist_ok=True)
        
        # Test with the DMZ firewall (which has compliance issues)
        config_file = current_dir / "dmz-firewall-01.cfg"
        baseline_file = mock_dir / "baseline" / "dmz-firewall-01.cfg"
        
        if config_file.exists() and baseline_file.exists():
            print(f"📄 Checking: {config_file.name}")
            
            result = check_config_compliance(
                str(config_file),
                str(baseline_file),
                skip_connectivity=True
            )
            result['file_path'] = str(config_file)
            
            # Show detailed results
            print(f"🏠 Hostname: {result['hostname']}")
            print(f"✅ Overall Compliant: {result['compliant']}")
            print(f"📋 Control Results:")
            
            for control, data in result.get('checks', {}).items():
                status = "PASS" if data.get('passed') else "FAIL"
                emoji = "✅" if data.get('passed') else "❌"
                print(f"   {emoji} {control}: {status}")
            
            # Write report
            write_result(result, str(output_dir))
            print(f"📄 Report saved to: {output_dir}")
            return True
        else:
            print("❌ Config files not found")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def demo_batch_processing():
    """Demo batch processing with multiple devices."""
    print("\n🚀 Demo 2: Batch Processing")
    print("-" * 40)
    
    try:
        # Create a simple batch processor for demo
        from scanner.config_checker import check_config_compliance
        
        mock_dir = Path("mock_configs")
        current_dir = mock_dir / "current"
        baseline_dir = mock_dir / "baseline"
        output_dir = Path("demo_output") / "batch"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        config_files = list(current_dir.glob("*.cfg"))
        print(f"📁 Processing {len(config_files)} devices...")
        
        all_results = []
        for i, config_file in enumerate(config_files, 1):
            baseline_file = baseline_dir / config_file.name
            if baseline_file.exists():
                print(f"   {i}/{len(config_files)}: {config_file.name}")
                
                result = check_config_compliance(
                    str(config_file),
                    str(baseline_file),
                    skip_connectivity=True
                )
                result['file_path'] = str(config_file)
                all_results.append(result)
        
        # Generate summary
        compliant = sum(1 for r in all_results if r.get('compliant', False))
        print(f"\n📊 Batch Results:")
        print(f"   Total devices: {len(all_results)}")
        print(f"   Compliant: {compliant}")
        print(f"   Non-compliant: {len(all_results) - compliant}")
        print(f"   Compliance rate: {(compliant/len(all_results)*100):.1f}%")
        
        # Save batch results
        batch_results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_devices': len(all_results),
                'compliant_devices': compliant,
                'compliance_rate': (compliant/len(all_results)*100) if all_results else 0
            },
            'device_results': all_results
        }
        
        with open(output_dir / "batch_results.json", 'w') as f:
            json.dump(batch_results, f, indent=2)
        
        print(f"💾 Batch results saved to: {output_dir}")
        return all_results
        
    except Exception as e:
        print(f"❌ Batch processing error: {e}")
        return []

def demo_dashboard_generation(results):
    """Demo HTML dashboard generation."""
    print("\n📊 Demo 3: Dashboard Generation")
    print("-" * 40)
    
    try:
        # Simple dashboard generator (since we can't import the full one without dependencies)
        output_dir = Path("demo_output")
        dashboard_path = output_dir / "demo_dashboard.html"
        
        # Calculate stats
        total_devices = len(results)
        compliant_devices = sum(1 for r in results if r.get('compliant', False))
        compliance_rate = (compliant_devices / total_devices * 100) if total_devices > 0 else 0
        
        # Generate simple HTML dashboard
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CMMC Compliance Dashboard - Demo</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 30px; text-align: center; border-radius: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; 
                     flex: 1; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .compliant {{ color: #27ae60; }}
        .non-compliant {{ color: #e74c3c; }}
        .device-list {{ background: white; padding: 20px; border-radius: 10px; 
                       box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .device {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .status-badge {{ padding: 5px 10px; border-radius: 15px; font-weight: bold; }}
        .badge-pass {{ background: #d4edda; color: #155724; }}
        .badge-fail {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CMMC 2.0 Level 1 Compliance Dashboard</h1>
        <p>Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number compliant">{compliant_devices}</div>
            <div>Compliant Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number non-compliant">{total_devices - compliant_devices}</div>
            <div>Non-Compliant</div>
        </div>
        <div class="stat-card">
            <div class="stat-number {'compliant' if compliance_rate >= 80 else 'non-compliant'}">{compliance_rate:.1f}%</div>
            <div>Compliance Rate</div>
        </div>
    </div>
    
    <div class="device-list">
        <h2>Device Details</h2>"""
        
        for result in results:
            hostname = result.get('hostname', 'Unknown')
            compliant = result.get('compliant', False)
            status_class = 'badge-pass' if compliant else 'badge-fail'
            status_text = 'Compliant' if compliant else 'Non-Compliant'
            
            checks = result.get('checks', {})
            passed_controls = sum(1 for check in checks.values() if check.get('passed', False))
            total_controls = len(checks)
            
            html_content += f"""
        <div class="device">
            <strong>{hostname}</strong>
            <span class="status-badge {status_class}">{status_text}</span>
            <span style="margin-left: 20px;">Controls: {passed_controls}/{total_controls}</span>
        </div>"""
        
        html_content += """
    </div>
</body>
</html>"""
        
        with open(dashboard_path, 'w') as f:
            f.write(html_content)
        
        print(f"📊 Dashboard created: {dashboard_path}")
        print(f"🌐 Open in browser: file://{dashboard_path.absolute()}")
        return True
        
    except Exception as e:
        print(f"❌ Dashboard generation error: {e}")
        return False

def demo_remediation_engine(results):
    """Demo remediation command generation."""
    print("\n🔧 Demo 4: Remediation Engine")
    print("-" * 40)
    
    try:
        output_dir = Path("demo_output") / "remediation"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate remediation for non-compliant devices
        non_compliant_devices = [r for r in results if not r.get('compliant', False)]
        
        if not non_compliant_devices:
            print("✅ All devices are compliant - no remediation needed!")
            return True
        
        print(f"🔧 Generating remediation for {len(non_compliant_devices)} devices...")
        
        master_script = output_dir / "master_remediation.txt"
        with open(master_script, 'w') as f:
            f.write("CMMC 2.0 Level 1 Remediation Plan\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}\n")
            f.write(f"Non-compliant devices: {len(non_compliant_devices)}\n\n")
            f.write("IMPORTANT: Always backup configurations before applying changes!\n\n")
        
        total_commands = 0
        for result in non_compliant_devices:
            hostname = result.get('hostname', 'Unknown')
            device_script = output_dir / f"{hostname}_remediation.txt"
            
            commands = []
            checks = result.get('checks', {})
            
            # Generate remediation commands based on failed controls
            for control, data in checks.items():
                if not data.get('passed', True):
                    if control == 'AC.L1-3.1.1' and not data.get('aaa_configured'):
                        commands.extend([
                            "! Configure AAA authentication",
                            "aaa authentication login default group tacacs+ local",
                            "tacacs-server host 192.168.1.100 key <your-key>"
                        ])
                    
                    if control == 'AC.L1-3.1.2':
                        if not data.get('enable_secret_present'):
                            commands.append("enable secret <strong-password>")
                        if not data.get('no_telnet'):
                            commands.extend([
                                "line vty 0 15",
                                " transport input ssh",
                                " no transport input telnet"
                            ])
                    
                    if control == 'SC.L1-3.13.1':
                        if not data.get('mgmt_acl_signal'):
                            commands.extend([
                                "ip access-list extended MGMT-ACL",
                                " permit tcp 192.168.100.0 0.0.0.255 any eq 22",
                                " deny ip any any",
                                "line vty 0 15",
                                " access-class MGMT-ACL in"
                            ])
                    
                    if control == 'SC.L1-3.13.5':
                        dmz_interfaces = data.get('dmz_interfaces_without_acl', [])
                        if dmz_interfaces:
                            commands.extend([
                                "ip access-list extended DMZ-ACL",
                                " permit tcp any host <dmz-server> eq 80",
                                " permit tcp any host <dmz-server> eq 443",
                                " deny ip any any"
                            ])
            
            # Write device-specific script
            with open(device_script, 'w') as f:
                f.write(f"Remediation for {hostname}\n")
                f.write("=" * 30 + "\n\n")
                f.write("BACKUP FIRST:\n")
                f.write("copy running-config startup-config\n\n")
                f.write("REMEDIATION COMMANDS:\n")
                for cmd in commands:
                    f.write(f"{cmd}\n")
                f.write("\nSAVE CONFIGURATION:\n")
                f.write("copy running-config startup-config\n")
            
            total_commands += len(commands)
            print(f"   📝 {hostname}: {len(commands)} commands")
        
        print(f"\n📋 Remediation Summary:")
        print(f"   Devices needing remediation: {len(non_compliant_devices)}")
        print(f"   Total remediation commands: {total_commands}")
        print(f"   Estimated time: {total_commands * 2} minutes")
        print(f"   Scripts saved to: {output_dir}")
        
        return True
        
    except Exception as e:
        print(f"❌ Remediation generation error: {e}")
        return False

def demo_command_line_interface():
    """Demo the command-line interface."""
    print("\n💻 Demo 5: Command-Line Interface")
    print("-" * 40)
    
    print("🔧 Available CLI commands:")
    print("   python -m cmmc_tool check --current ./mock_configs/current --baseline ./mock_configs/baseline")
    print("   python -m cmmc_tool batch --current ./configs --baseline ./baseline --workers 8")
    print("   python -m cmmc_tool remediate --results ./results.json --output ./remediation")
    print("   python -m cmmc_tool validate --config ./device.cfg --type cisco_router")
    print("   python -m cmmc_tool report --results ./results --pdf --dashboard")
    
    print(f"\n💡 Try running:")
    print(f"   python demo_enhanced_features.py cli-demo")
    
    return True

def main():
    """Run all demos."""
    print("🎉 CMMC Tool Enhanced Features Demo")
    print("=" * 60)
    
    # Run demos in sequence
    if not demo_basic_compliance_check():
        return
    
    results = demo_batch_processing()
    if not results:
        return
    
    demo_dashboard_generation(results)
    demo_remediation_engine(results)
    demo_command_line_interface()
    
    print(f"\n🎊 Demo Complete!")
    print(f"📁 Check the demo_output/ folder for all generated files:")
    print(f"   • Compliance reports (TXT/CSV)")
    print(f"   • HTML dashboard")
    print(f"   • Remediation scripts")
    print(f"   • Batch processing results (JSON)")
    
    print(f"\n🚀 Next steps:")
    print(f"   1. Run your GUI: python main_gui.py")
    print(f"   2. Try the mock environment with your tool")
    print(f"   3. Explore the enhanced features!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "cli-demo":
        demo_command_line_interface()
    else:
        main()