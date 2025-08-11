# tests/integration/test_end_to_end.py
import pytest
import os
from pathlib import Path
from scanner.config_checker import check_config_compliance
from reporter.simple_report import write_result

class TestEndToEndWorkflow:
    def test_complete_compliance_workflow(self, temp_config_dir, tmp_path):
        """Test the complete workflow from config files to reports."""
        current_path = f"{temp_config_dir}/cisco_test.cfg"
        baseline_path = f"{temp_config_dir}/cisco_test.cfg"
        output_dir = tmp_path / "output"
        
        # Run compliance check
        result = check_config_compliance(current_path, baseline_path, skip_connectivity=True)
        result["file_path"] = current_path
        
        # Generate report
        write_result(result, str(output_dir))
        
        # Verify outputs exist
        assert (output_dir / "compliance_result.txt").exists()
        assert (output_dir / "compliance_result.csv").exists()
        
        # Verify report contents
        with open(output_dir / "compliance_result.txt", "r") as f:
            content = f.read()
            assert "TestRouter01" in content
            assert "Compliance Status:" in content
            assert "Control Checks:" in content
