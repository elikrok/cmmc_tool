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
