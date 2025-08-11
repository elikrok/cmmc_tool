# setup_mock_environment.py
"""Script to create mock network environment for testing CMMC tool."""

import os
from pathlib import Path

def create_mock_environment():
    """Create mock configuration files for testing."""
    
    # Create directory structure
    base_dir = Path("mock_configs")
    current_dir = base_dir / "current"
    baseline_dir = base_dir / "baseline"
    
    current_dir.mkdir(parents=True, exist_ok=True)
    baseline_dir.mkdir(parents=True, exist_ok=True)
    
    # Current configurations (with some compliance issues)
    configs = {
        "edge-router-01.cfg": """!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname EdgeRouter01
!
boot-start-marker
boot-end-marker
!
! Missing enable secret - COMPLIANCE ISSUE
! Missing AAA configuration - COMPLIANCE ISSUE
!
multilink bundle-name authenticated
!
crypto pki token default removal timeout 0
!
license udi pid CISCO2921/K9 sn FCZ1648C0QJ
!
redundancy
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny   ip any any
!
ip access-list extended WAN-IN
 permit tcp any host 203.0.113.1 eq 22
 permit tcp any host 203.0.113.1 eq 443
 deny   ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
 ip access-group WAN-IN in
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Connection to Core Switch
 ip address 10.1.1.1 255.255.255.0
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 shutdown
 duplex auto
 speed auto
!
router ospf 1
 log-adjacency-changes
 network 10.1.0.0 0.0.255.255 area 0
!
ip forward-protocol nd
!
no ip http server
no ip http secure-server
!
control-plane
!
line con 0
line aux 0
line vty 0 4
 login local
 transport input ssh telnet
 ! Missing access-class - COMPLIANCE ISSUE
line vty 5 15
 login local
 transport input ssh telnet
 ! Missing access-class - COMPLIANCE ISSUE
!
end""",

        "core-switch-01.cfg": """!
hostname CoreSwitch01
!
management ssh
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
username readonly privilege 1 secret readpass
!
aaa authentication login default group tacacs+ local
aaa group server tacacs+ TACACS-SERVERS
 server 10.1.100.10
 server 10.1.100.11
!
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
ip access-list extended DMZ-IN
 10 permit tcp any host 10.1.50.10 eq 80
 20 permit tcp any host 10.1.50.10 eq 443
 30 permit tcp any host 10.1.50.20 eq 25
 40 deny ip any any
!
vlan 100
 name Management
!
vlan 200
 name Users
!
vlan 300
 name Servers
!
vlan 500
 name DMZ
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Vlan100
 description Management VLAN
 ip address 10.1.100.1/24
!
interface Vlan200
 description User VLAN
 ip address 10.1.200.1/24
!
interface Vlan300
 description Server VLAN
 ip address 10.1.30.1/24
!
interface Vlan500
 description DMZ VLAN
 ip address 10.1.50.1/24
 ip access-group DMZ-IN in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,500
!
interface Ethernet2
 description User Access Port
 switchport mode access
 switchport access vlan 200
!
interface Ethernet3
 description Server Access Port
 switchport mode access
 switchport access vlan 300
!
interface Ethernet4
 description DMZ Access Port
 switchport mode access
 switchport access vlan 500
!
line vty 0 4
 login local
 transport input ssh
!
end""",

        "dmz-firewall-01.cfg": """!
hostname DMZFirewall01
!
! Missing enable secret - COMPLIANCE ISSUE
!
! Missing proper user accounts - COMPLIANCE ISSUE
username fwadmin privilege 15 password plaintext123
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key sharedkey123
tacacs-server host 10.1.100.12 key sharedkey123
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 permit tcp any host 10.1.50.20 eq 25
 permit tcp any host 10.1.50.20 eq 587
 deny ip any any
!
ip access-list extended DMZ-TO-INSIDE
 permit tcp host 10.1.50.10 10.1.30.0 0.0.0.255 eq 3306
 permit tcp host 10.1.50.20 10.1.30.0 0.0.0.255 eq 3306
 deny ip any any
!
ip access-list extended MGMT-ACCESS
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
interface GigabitEthernet0/0
 description Outside/WAN Interface
 ip address 203.0.113.50 255.255.255.0
 ip access-group OUTSIDE-IN in
!
interface GigabitEthernet0/1
 description DMZ Interface
 ip address 10.1.50.254 255.255.255.0
 ! Missing ACL - COMPLIANCE ISSUE
!
interface GigabitEthernet0/2
 description Inside Interface
 ip address 10.1.30.254 255.255.255.0
 ip access-group DMZ-TO-INSIDE in
!
router ospf 1
 network 10.1.30.0 0.0.0.255 area 0
 network 10.1.50.0 0.0.0.255 area 0
!
line vty 0 4
 login local
 transport input ssh telnet
 ! Telnet enabled - COMPLIANCE ISSUE
 access-class MGMT-ACCESS in
!
end"""
    }
    
    # Baseline configurations (compliant versions)
    baseline_configs = {
        "edge-router-01.cfg": """!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname EdgeRouter01
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$SAFE$complianthashere789
!
username admin privilege 15 secret adminpass123
username operator privilege 5 secret operatorpass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
multilink bundle-name authenticated
!
crypto pki token default removal timeout 0
!
license udi pid CISCO2921/K9 sn FCZ1648C0QJ
!
redundancy
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny   ip any any
!
ip access-list extended WAN-IN
 permit tcp any host 203.0.113.1 eq 22
 permit tcp any host 203.0.113.1 eq 443
 deny   ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
 ip access-group WAN-IN in
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Connection to Core Switch
 ip address 10.1.1.1 255.255.255.0
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 shutdown
 duplex auto
 speed auto
!
router ospf 1
 log-adjacency-changes
 network 10.1.0.0 0.0.255.255 area 0
!
ip forward-protocol nd
!
no ip http server
no ip http secure-server
!
control-plane
!
line con 0
line aux 0
line vty 0 4
 login local
 transport input ssh
 access-class VTY-MGMT in
line vty 5 15
 login local
 transport input ssh
 access-class VTY-MGMT in
!
end""",

        "core-switch-01.cfg": """!
hostname CoreSwitch01
!
management ssh
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
username readonly privilege 1 secret readpass
!
aaa authentication login default group tacacs+ local
aaa group server tacacs+ TACACS-SERVERS
 server 10.1.100.10
 server 10.1.100.11
!
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
ip access-list extended DMZ-IN
 10 permit tcp any host 10.1.50.10 eq 80
 20 permit tcp any host 10.1.50.10 eq 443
 30 permit tcp any host 10.1.50.20 eq 25
 40 deny ip any any
!
vlan 100
 name Management
!
vlan 200
 name Users
!
vlan 300
 name Servers
!
vlan 500
 name DMZ
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Vlan100
 description Management VLAN
 ip address 10.1.100.1/24
!
interface Vlan200
 description User VLAN
 ip address 10.1.200.1/24
!
interface Vlan300
 description Server VLAN
 ip address 10.1.30.1/24
!
interface Vlan500
 description DMZ VLAN
 ip address 10.1.50.1/24
 ip access-group DMZ-IN in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,500
!
interface Ethernet2
 description User Access Port
 switchport mode access
 switchport access vlan 200
!
interface Ethernet3
 description Server Access Port
 switchport mode access
 switchport access vlan 300
!
interface Ethernet4
 description DMZ Access Port
 switchport mode access
 switchport access vlan 500
!
line vty 0 4
 login local
 transport input ssh
!
end""",

        "dmz-firewall-01.cfg": """!
hostname DMZFirewall01
!
enable secret 5 $1$WXYZ$anotherhashhere456
!
username fwadmin privilege 15 secret fwpass123
username security privilege 10 secret secpass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key sharedkey123
tacacs-server host 10.1.100.12 key sharedkey123
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 permit tcp any host 10.1.50.20 eq 25
 permit tcp any host 10.1.50.20 eq 587
 deny ip any any
!
ip access-list extended DMZ-TO-INSIDE
 permit tcp host 10.1.50.10 10.1.30.0 0.0.0.255 eq 3306
 permit tcp host 10.1.50.20 10.1.30.0 0.0.0.255 eq 3306
 deny ip any any
!
ip access-list extended MGMT-ACCESS
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
ip access-list extended DMZ-PROTECTION
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 deny ip any any
!
interface GigabitEthernet0/0
 description Outside/WAN Interface
 ip address 203.0.113.50 255.255.255.0
 ip access-group OUTSIDE-IN in
!
interface GigabitEthernet0/1
 description DMZ Interface
 ip address 10.1.50.254 255.255.255.0
 ip access-group DMZ-PROTECTION in
!
interface GigabitEthernet0/2
 description Inside Interface
 ip address 10.1.30.254 255.255.255.0
 ip access-group DMZ-TO-INSIDE in
!
router ospf 1
 network 10.1.30.0 0.0.0.255 area 0
 network 10.1.50.0 0.0.0.255 area 0
!
line vty 0 4
 login local
 transport input ssh
 access-class MGMT-ACCESS in
!
end"""
    }
    
    print("Creating mock network environment...")
    
    # Write current configuration files
    for filename, content in configs.items():
        file_path = current_dir / filename
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Created: {file_path}")
    
    # Write baseline configuration files
    for filename, content in baseline_configs.items():
        file_path = baseline_dir / filename
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Created: {file_path}")
    
    print(f"\nMock environment created successfully!")
    print(f"Current configs: {current_dir}")
    print(f"Baseline configs: {baseline_dir}")
    print(f"\nTo test your tool:")
    print(f"1. Run: python main_gui.py")
    print(f"2. Select current folder: {current_dir.absolute()}")
    print(f"3. Select baseline folder: {baseline_dir.absolute()}")
    print(f"4. Click 'Run Compliance Check'")
    print(f"\nExpected results:")
    print(f"- EdgeRouter01: NON-COMPLIANT (missing AAA, enable secret, VTY ACL)")
    print(f"- CoreSwitch01: COMPLIANT (all controls pass)")
    print(f"- DMZFirewall01: NON-COMPLIANT (password issues, telnet enabled, missing DMZ ACL)")

def create_test_runner():
    """Create a test runner script."""
    test_script = """#!/usr/bin/env python3
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
            print(f"\\nChecking {config_file.name}...")
            
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
        print(f"\\nTest Summary:")
        print(f"   Total devices: {len(results)}")
        compliant = sum(1 for r in results if r.get('compliant', False))
        print(f"   Compliant: {compliant}")
        print(f"   Non-compliant: {len(results) - compliant}")
        print(f"   Compliance rate: {(compliant/len(results)*100):.1f}%")
        print(f"   Output directory: {output_dir.absolute()}")
        
        print(f"\\nTest completed successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR: Test failed: {e}")
        return False

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
"""
    
    with open("test_cmmc_tool.py", "w", encoding="utf-8") as f:
        f.write(test_script)
    
    print("Created test runner: test_cmmc_tool.py")

if __name__ == "__main__":
    create_mock_environment()
    create_test_runner()
    print(f"\n🚀 Ready to test! You can now:")
    print(f"   • Run the GUI: python main_gui.py")
    print(f"   • Run automated test: python test_cmmc_tool.py")
    print(f"   • Check mock configs in: mock_configs/")