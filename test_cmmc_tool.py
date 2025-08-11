#!/usr/bin/env python3
# test_cmmc_tool.py - Automated test runner for CMMC tool

import subprocess
import sys
from pathlib import Path

def run_test():
    print("Testing CMMC Tool with Mock Environment")
    print("=" * 60)
    
    # Check if mock environment exists
    mock_dir = Path("mock_configs")
    if not mock_dir.exists():
        print("ERROR: Mock environment not found. Run setup_mock_environment.py first.")
        return False
    
    current_dir = mock_dir / "current"
    baseline_dir = mock_dir / "baseline"
    output_dir = Path("test_output")
    
    # Clean previous test output
    if output_dir.exists():
        import shutil
        shutil.rmtree(output_dir)
    
    try:
        # Import and run the compliance checker
        from scanner.config_checker import check_config_compliance
        from reporter.simple_report import write_result
        
        output_dir.mkdir(exist_ok=True)
        
        config_files = list(current_dir.glob("*.cfg"))
        print(f"Found {len(config_files)} configuration files")
        
        results = []
        for config_file in config_files:
            baseline_file = baseline_dir / config_file.name
            print(f"\nChecking {config_file.name}...")
            
            result = check_config_compliance(
                str(config_file),
                str(baseline_file),
                skip_connectivity=True
            )
            result['file_path'] = str(config_file)
            
            # Write individual result
            write_result(result, str(output_dir))
            results.append(result)
            
            # Show result summary
            status = "COMPLIANT" if result['compliant'] else "NON-COMPLIANT"
            print(f"   Result: {status}")
            
            # Show failed controls
            failed_controls = [
                control for control, data in result.get('checks', {}).items()
                if not data.get('passed', True)
            ]
            if failed_controls:
                print(f"   Failed controls: {', '.join(failed_controls)}")
        
        # Summary
        print(f"\nTest Summary:")
        print(f"   Total devices: {len(results)}")
        compliant = sum(1 for r in results if r.get('compliant', False))
        print(f"   Compliant: {compliant}")
        print(f"   Non-compliant: {len(results) - compliant}")
        print(f"   Compliance rate: {(compliant/len(results)*100):.1f}%")
        print(f"   Output directory: {output_dir.absolute()}")
        
        print(f"\nTest completed successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR: Test failed: {e}")
        return False

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
