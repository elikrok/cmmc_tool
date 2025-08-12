# test_multivendor.py
from enhanced_features.vendor_manager import VendorManager, VendorType

def test_vendor_detection():
    manager = VendorManager()
    
    # Test Cisco detection
    cisco_config = """
    version 15.7
    hostname CiscoRouter01
    aaa authentication login default group tacacs+ local
    """
    
    vendor_type, version = manager.detect_vendor(cisco_config)
    print(f"Detected: {vendor_type.value}, Version: {version}")
    
    # Test Arista detection
    arista_config = """
    hostname AristaSwitch01
    management ssh
    username admin role network-admin
    """
    
    vendor_type, version = manager.detect_vendor(arista_config)
    print(f"Detected: {vendor_type.value}, Version: {version}")

if __name__ == "__main__":
    test_vendor_detection()