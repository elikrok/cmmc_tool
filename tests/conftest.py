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
