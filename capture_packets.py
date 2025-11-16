#!/usr/bin/env python3
"""Simple packet capture script for SecureChat traffic analysis."""

import subprocess
import sys
import time
import os
from datetime import datetime

def start_tcpdump_capture(interface="lo", port=8443, output_file=None):
    """Start tcpdump capture for SecureChat traffic."""
    
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"securechat_capture_{timestamp}.pcap"
    
    print(f"Starting packet capture on {interface}:{port}")
    print(f"Output file: {output_file}")
    print("Press Ctrl+C to stop capture")
    
    # Build tcpdump command
    cmd = [
        "sudo", "tcpdump",
        "-i", interface,      # Interface
        "-w", output_file,    # Write to file
        "-s", "0",           # Capture full packets
        "port", str(port)    # Filter by port
    ]
    
    try:
        # Start tcpdump
        process = subprocess.Popen(cmd)
        
        print(f"Capture started (PID: {process.pid})")
        print("Now run your SecureChat client and server...")
        
        # Wait for user to stop
        process.wait()
        
    except KeyboardInterrupt:
        print("\nStopping capture...")
        process.terminate()
        process.wait()
        
    print(f"Capture saved to: {output_file}")
    return output_file

def analyze_capture_file(pcap_file):
    """Analyze captured pcap file."""
    print(f"\nAnalyzing {pcap_file}...")
    
    # Show basic statistics
    cmd = ["tcpdump", "-r", pcap_file, "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        print(f"Total packets captured: {len(lines)}")
        
        # Show first few packets
        print("\nFirst 5 packets:")
        for i, line in enumerate(lines[:5]):
            print(f"  {i+1}: {line}")
            
    except Exception as e:
        print(f"Error analyzing file: {e}")

def show_hex_data(pcap_file, packet_num=None):
    """Show hex data from specific packet."""
    if packet_num:
        cmd = ["tcpdump", "-r", pcap_file, "-X", f"-c {packet_num}"]
    else:
        cmd = ["tcpdump", "-r", pcap_file, "-X", "-c", "1"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print("\nPacket hex data:")
        print(result.stdout)
    except Exception as e:
        print(f"Error showing hex data: {e}")

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Packet Capture Tool")
    parser.add_argument("-i", "--interface", default="lo", help="Network interface (default: lo)")
    parser.add_argument("-p", "--port", type=int, default=8443, help="Port to capture (default: 8443)")
    parser.add_argument("-o", "--output", help="Output pcap file")
    parser.add_argument("-a", "--analyze", help="Analyze existing pcap file")
    parser.add_argument("--hex", help="Show hex data from pcap file")
    
    args = parser.parse_args()
    
    if args.analyze:
        analyze_capture_file(args.analyze)
        if input("Show hex data? (y/n): ").lower() == 'y':
            show_hex_data(args.analyze)
    
    elif args.hex:
        show_hex_data(args.hex)
        
    else:
        # Check if running as root
        if os.geteuid() != 0:
            print("Note: You may need to run as root (sudo) for packet capture")
        
        # Start capture
        output_file = start_tcpdump_capture(args.interface, args.port, args.output)
        
        # Analyze results
        if os.path.exists(output_file):
            analyze_capture_file(output_file)

if __name__ == "__main__":
    main()