# tests/conftest.py
import pytest
import tempfile
import os
from pathlib import Path

@pytest.fixture
def temp_config_dir():
    """Create a temporary directory with test config files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test configs
        cisco_config = """!
hostname TestRouter01
!
aaa authentication login default group tacacs+ local
tacacs-server host 192.168.1.100 key testkey
!
enable secret 5 $1$test$hash
!
username admin privilege 15 secret password
username operator privilege 5 secret password
!
line vty 0 4
 login local
 transport input ssh
 access-class MGMT-ACL in
!
ip access-list extended MGMT-ACL
 permit tcp 192.168.1.0 0.0.0.255 any eq 22
 deny ip any any
!
        """
        
        arista_config = """!
hostname TestSwitch01
!
management ssh
!
aaa authentication login default group tacacs+ local
tacacs-server host 192.168.1.100 key testkey
!
username admin role network-admin
!
interface Management1
 ip address 192.168.1.10/24
 ip access-group MGMT-IN in
!
ip access-list MGMT-IN
 10 permit tcp 192.168.1.0/24 any eq ssh
 20 deny ip any any
!
        """
        
        with open(f"{tmpdir}/cisco_test.cfg", "w") as f:
            f.write(cisco_config)
        with open(f"{tmpdir}/arista_test.cfg", "w") as f:
            f.write(arista_config)
            
        yield tmpdir

@pytest.fixture
def sample_compliance_result():
    """Sample compliance check result for testing."""
    return {
        "hostname": "TestDevice01",
        "compliant": True,
        "checks": {
            "CM.L1-3.4.1": {"passed": True, "missing_lines": [], "extra_lines": []},
            "AC.L1-3.1.1": {"passed": True, "aaa_configured": True, "tacacs_servers": ["192.168.1.100"]},
            "AC.L1-3.1.2": {"passed": True, "enable_secret_present": True, "no_telnet": True},
            "SC.L1-3.13.1": {"passed": True, "ssh_mgmt": True, "acls_present_and_applied": True},
            "SC.L1-3.13.5": {"passed": True, "dmz_interfaces_without_acl": []}
        }
    }

# tests/unit/test_config_checker.py
import pytest
from scanner.config_checker import (
    extract_hostname, 
    _aaa_is_configured, 
    _find_tacacs_servers,
    _ac_limit_transactions,
    check_config_compliance
)

class TestHostnameExtraction:
    def test_extract_hostname_cisco(self, temp_config_dir):
        config_path = f"{temp_config_dir}/cisco_test.cfg"
        hostname = extract_hostname(config_path)
        assert hostname == "TestRouter01"
    
    def test_extract_hostname_arista(self, temp_config_dir):
        config_path = f"{temp_config_dir}/arista_test.cfg"
        hostname = extract_hostname(config_path)
        assert hostname == "TestSwitch01"
    
    def test_extract_hostname_missing_returns_unknown(self, tmp_path):
        config_file = tmp_path / "no_hostname.cfg"
        config_file.write_text("interface gi0/0\n ip address 1.1.1.1 255.255.255.0\n")
        assert extract_hostname(str(config_file)) == "unknown"

class TestAAAConfiguration:
    def test_aaa_configured_with_tacacs_and_local(self):
        lines = [
            "aaa authentication login default group tacacs+ local",
            "tacacs-server host 192.168.1.100"
        ]
        assert _aaa_is_configured(lines) == True
    
    def test_aaa_configured_tacacs_group(self):
        lines = [
            "aaa authentication login default group TAC-GROUP local",
            "aaa group server tacacs+ TAC-GROUP",
            " server 192.168.1.100"
        ]
        assert _aaa_is_configured(lines) == True
    
    def test_aaa_not_configured_missing_local(self):
        lines = [
            "aaa authentication login default group tacacs+"
        ]
        assert _aaa_is_configured(lines) == False

class TestTACACSServers:
    def test_find_tacacs_servers_single_line(self):
        lines = [
            "tacacs-server host 192.168.1.100 key mykey",
            "tacacs-server host 192.168.1.101"
        ]
        servers = _find_tacacs_servers(lines)
        assert "192.168.1.100" in servers
        assert "192.168.1.101" in servers
        assert len(servers) == 2
    
    def test_find_tacacs_servers_group_block(self):
        lines = [
            "aaa group server tacacs+ MYGROUP",
            " server 192.168.1.200",
            " server 192.168.1.201"
        ]
        servers = _find_tacacs_servers(lines)
        assert "192.168.1.200" in servers
        assert "192.168.1.201" in servers

class TestAccessControl:
    def test_ac_limit_transactions_compliant(self):
        lines = [
            "enable secret 5 $1$hash$test",
            "username admin privilege 5 secret test",
            "line vty 0 4",
            " transport input ssh"
        ]
        assert _ac_limit_transactions(lines) == True
    
    def test_ac_limit_transactions_telnet_fails(self):
        lines = [
            "enable secret 5 $1$hash$test",
            "username admin privilege 5 secret test",
            "line vty 0 4",
            " transport input telnet"
        ]
        assert _ac_limit_transactions(lines) == False

class TestIntegration:
    def test_full_compliance_check(self, temp_config_dir):
        current_path = f"{temp_config_dir}/cisco_test.cfg"
        baseline_path = f"{temp_config_dir}/cisco_test.cfg"  # Same file for simplicity
        
        result = check_config_compliance(current_path, baseline_path, skip_connectivity=True)
        
        assert result["hostname"] == "TestRouter01"
        assert "checks" in result
        assert "CM.L1-3.4.1" in result["checks"]
        assert "AC.L1-3.1.1" in result["checks"]
        assert "AC.L1-3.1.2" in result["checks"]
        assert "SC.L1-3.13.1" in result["checks"]
        assert "SC.L1-3.13.5" in result["checks"]

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
