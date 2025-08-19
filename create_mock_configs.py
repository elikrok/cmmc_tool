"""Create mock network configuration files for CMMC compliance testing."""

from pathlib import Path

def create_mock_configs():
    """Create mock environment with sample network configurations."""
    try:
        print("🏗️ Creating mock environment...")
        
        # Create directory structure
        base_dir = Path("mock_configs")
        current_dir = base_dir / "current"
        baseline_dir = base_dir / "baseline"
        
        current_dir.mkdir(parents=True, exist_ok=True)
        baseline_dir.mkdir(parents=True, exist_ok=True)
        
        # Current configurations (with compliance issues)
        current_configs = {
            "edge-router-01.cfg": """!
version 15.7
hostname EdgeRouter01
!
! Missing enable secret - COMPLIANCE ISSUE
! Missing AAA configuration - COMPLIANCE ISSUE
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 description LAN Connection
 ip address 10.1.1.1 255.255.255.0
!
line vty 0 4
 login local
 transport input ssh telnet
 ! Missing access-class - COMPLIANCE ISSUE
!
end""",

            "core-switch-01.cfg": """!
hostname CoreSwitch01
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
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
username fwadmin privilege 15 password plaintext123
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key sharedkey123
!
ip access-list extended OUTSIDE-IN
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
 ! Missing ACL - COMPLIANCE ISSUE
!
line vty 0 4
 login local
 transport input ssh telnet
 ! Telnet enabled - COMPLIANCE ISSUE
!
end"""
        }
        
        # Baseline configurations (compliant versions)
        baseline_configs = {
            "edge-router-01.cfg": """!
version 15.7
hostname EdgeRouter01
!
enable secret 5 $1$SAFE$complianthashere789
!
username admin privilege 15 secret adminpass123
username operator privilege 5 secret operatorpass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key supersecretkey
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 description LAN Connection
 ip address 10.1.1.1 255.255.255.0
!
line vty 0 4
 login local
 transport input ssh
 access-class VTY-MGMT in
!
end""",

            "core-switch-01.cfg": """!
hostname CoreSwitch01
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
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
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
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
line vty 0 4
 login local
 transport input ssh
!
end"""
        }
        
        # Write current configuration files
        for filename, content in current_configs.items():
            file_path = current_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Created: {file_path}")
        
        # Write baseline configuration files
        for filename, content in baseline_configs.items():
            file_path = baseline_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Created: {file_path}")
        
        print("✅ Mock environment created successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error creating mock environment: {e}")
        return False

if __name__ == "__main__":
    create_mock_configs()