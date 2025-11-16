#!/usr/bin/env python3
"""Test network connectivity to Windows host."""

import socket
import os
from dotenv import load_dotenv

def test_network():
    """Test network connectivity."""
    # Load .env file
    if os.path.exists('.env'):
        load_dotenv()
        print("✓ Loaded .env file")
    else:
        print("✗ No .env file found")
    
    # Get host from environment
    host = os.getenv('DB_HOST', '192.168.88.1')
    port = int(os.getenv('DB_PORT', 3305))
    
    print(f"\nTesting network connectivity to {host}:{port}")
    
    try:
        # Test basic connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✓ Port {port} is open on {host}")
            return True
        else:
            print(f"✗ Port {port} is closed or filtered on {host}")
            return False
            
    except socket.gaierror as e:
        print(f"✗ DNS resolution failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Network test failed: {e}")
        return False

def test_multiple_ips():
    """Test connectivity to different possible IPs."""
    possible_ips = [
        '192.168.88.1',   # VMnet1 (Host-only)
        '192.168.118.1',  # VMnet8 (NAT)
        '192.168.0.218',  # Wi-Fi (from ipconfig)
        'localhost',       # Local test
        '127.0.0.1'       # Local test
    ]
    
    port = 3305
    print(f"\nTesting multiple possible Windows host IPs on port {port}:")
    
    working_ips = []
    for ip in possible_ips:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                print(f"✓ {ip}:{port} - OPEN")
                working_ips.append(ip)
            else:
                print(f"✗ {ip}:{port} - CLOSED/FILTERED")
        except Exception as e:
            print(f"✗ {ip}:{port} - ERROR: {e}")
    
    if working_ips:
        print(f"\n✓ Working IPs: {', '.join(working_ips)}")
        print(f"Use one of these in your .env file as DB_HOST")
    else:
        print(f"\n✗ No working IPs found. Check:")
        print("  1. MySQL container is running on Windows")
        print("  2. Windows firewall allows port 3305")
        print("  3. Network configuration in VMware")

if __name__ == '__main__':
    print("=== Network Connectivity Test ===")
    test_network()
    print("\n=== Testing Multiple IPs ===")
    test_multiple_ips()