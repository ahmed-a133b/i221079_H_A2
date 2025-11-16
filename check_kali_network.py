#!/usr/bin/env python3
"""Find Kali VM network configuration."""

import subprocess
import re
import socket

def get_kali_ip():
    """Get Kali VM IP addresses."""
    print("=== Kali Linux Network Configuration ===\n")
    
    try:
        # Run ip addr show
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Network interfaces:")
            
            # Parse interfaces and IPs
            interfaces = {}
            current_interface = None
            
            for line in result.stdout.split('\n'):
                # Interface line (e.g., "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>")
                if re.match(r'^\d+:', line):
                    current_interface = line.split(':')[1].strip()
                    interfaces[current_interface] = []
                
                # IP address line (e.g., "    inet 192.168.88.10/24 brd 192.168.88.255 scope global eth0")
                elif 'inet ' in line and current_interface:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip != '127.0.0.1':  # Skip localhost
                            interfaces[current_interface].append(ip)
            
            # Display results
            vmware_ips = []
            for interface, ips in interfaces.items():
                if ips:
                    for ip in ips:
                        print(f"  {interface}: {ip}")
                        # Check if it's likely a VMware IP
                        if (ip.startswith('192.168.88.') or 
                            ip.startswith('192.168.118.') or 
                            ip.startswith('192.168.0.')):
                            vmware_ips.append(ip)
            
            print(f"\nLikely VMware network IPs: {vmware_ips}")
            
            if vmware_ips:
                print(f"\n✓ Use one of these IPs for SERVER_HOST if running server on different machine")
                print(f"✓ Current config uses 0.0.0.0 (all interfaces) which should work")
                return vmware_ips[0]
            else:
                print("\n✗ No VMware network IPs found")
                return None
        
    except FileNotFoundError:
        print("'ip' command not found, trying alternative method...")
        
        # Alternative method using hostname -I
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            if result.returncode == 0:
                ips = result.stdout.strip().split()
                print(f"All IPs: {ips}")
                for ip in ips:
                    if not ip.startswith('127.'):
                        print(f"Non-localhost IP: {ip}")
                        return ip
        except:
            pass
    
    return None

def test_server_binding():
    """Test if we can bind to port 8443."""
    print("\n=== Testing Server Port Binding ===")
    
    test_configs = [
        ('0.0.0.0', 8443),
        ('localhost', 8443),
        ('127.0.0.1', 8443)
    ]
    
    for host, port in test_configs:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.close()
            print(f"✓ Can bind to {host}:{port}")
        except Exception as e:
            print(f"✗ Cannot bind to {host}:{port} - {e}")

if __name__ == '__main__':
    kali_ip = get_kali_ip()
    test_server_binding()
    
    print("\n=== Recommended Setup ===")
    print("1. For SERVER (on Kali): Copy .env.kali.server to .env")
    print("2. For CLIENT (on Kali): Copy .env.kali.client to .env")
    print("3. Run server: python3 -m app.server")
    print("4. Run client: python3 -m app.client")