# test_runner.py - Quick test of your CMMC tool
import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.getcwd())

def test_imports():
    """Test if all modules import correctly."""
    print("🔍 Testing imports...")
    try:
        from scanner.config_checker import check_config_compliance, extract_hostname
        from reporter.simple_report import write_result
        print("✅ All modules imported successfully!")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_config_checker():
    """Test the config checker with your existing files."""
    print("\n🔍 Testing config checker...")
    
    try:
        from scanner.config_checker import check_config_compliance
        
        # Find existing config files
        config_files = list(Path(".").glob("**/*.cfg"))
        if not config_files:
            print("❌ No .cfg files found in current directory")
            return False
            
        print(f"📁 Found {len(config_files)} config files:")
        for cfg in config_files:
            print(f"   - {cfg}")
        
        # Test with first two configs (or same file twice if only one)
        current_config = str(config_files[0])
        baseline_config = str(config_files[1] if len(config_files) > 1 else config_files[0])
        
        print(f"\n🧪 Testing with:")
        print(f"   Current:  {current_config}")
        print(f"   Baseline: {baseline_config}")
        
        # Run the compliance check
        result = check_config_compliance(
            current_config, 
            baseline_config, 
            skip_connectivity=True  # Skip network tests for safety
        )
        
        print(f"\n📊 Results for {result['hostname']}:")
        print(f"   Overall Compliant: {result['compliant']}")
        
        # Show individual control results
        for control, data in result.get('checks', {}).items():
            status = "✅ PASS" if data.get('passed') else "❌ FAIL"
            print(f"   {control}: {status}")
            
        return True
        
    except Exception as e:
        print(f"❌ Config checker test failed: {e}")
        return False

def test_reporter():
    """Test the reporter functionality."""
    print("\n🔍 Testing reporter...")
    
    try:
        from scanner.config_checker import check_config_compliance
        from reporter.simple_report import write_result
        
        # Find a config file
        config_files = list(Path(".").glob("**/*.cfg"))
        if not config_files:
            print("❌ No .cfg files found for reporter test")
            return False
            
        current_config = str(config_files[0])
        baseline_config = str(config_files[0])  # Use same file
        
        # Run compliance check
        result = check_config_compliance(current_config, baseline_config, skip_connectivity=True)
        result["file_path"] = current_config
        
        # Test output directory
        output_dir = Path("test_output")
        output_dir.mkdir(exist_ok=True)
        
        # Generate report
        write_result(result, str(output_dir))
        
        # Check if files were created
        txt_file = output_dir / "compliance_result.txt"
        csv_file = output_dir / "compliance_result.csv"
        
        if txt_file.exists() and csv_file.exists():
            print("✅ Report files generated successfully!")
            print(f"   📄 {txt_file} ({txt_file.stat().st_size} bytes)")
            print(f"   📄 {csv_file} ({csv_file.stat().st_size} bytes)")
            
            # Show a sample of the text report
            print(f"\n📋 Sample from {txt_file}:")
            with open(txt_file, 'r') as f:
                lines = f.readlines()[:10]  # First 10 lines
                for line in lines:
                    print(f"   {line.rstrip()}")
            
            return True
        else:
            print("❌ Report files were not created")
            return False
            
    except Exception as e:
        print(f"❌ Reporter test failed: {e}")
        return False

def test_gui_imports():
    """Test if GUI components can be imported."""
    print("\n🔍 Testing GUI imports...")
    
    try:
        import tkinter as tk
        print("✅ Tkinter available")
        
        # Test if your GUI modules import
        if Path("ui/folder_gui.py").exists():
            sys.path.insert(0, "ui")
            import folder_gui
            print("✅ folder_gui.py imports successfully")
        
        if Path("main_gui.py").exists():
            import main_gui
            print("✅ main_gui.py imports successfully")
            
        return True
        
    except Exception as e:
        print(f"❌ GUI test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 CMMC Tool Test Runner")
    print("=" * 50)
    
    tests = [
        ("Module Imports", test_imports),
        ("Config Checker", test_config_checker),
        ("Report Generator", test_reporter),
        ("GUI Components", test_gui_imports),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        print("-" * 30)
        success = test_func()
        results.append((test_name, success))
        
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your CMMC tool is working correctly.")
        print("\n💡 Next steps:")
        print("   1. Run 'python main_gui.py' to start the GUI")
        print("   2. Set up the CI/CD pipeline with the provided files")
        print("   3. Let's discuss additional features!")
    else:
        print("⚠️  Some tests failed. Let's debug the issues.")

if __name__ == "__main__":
    main()
