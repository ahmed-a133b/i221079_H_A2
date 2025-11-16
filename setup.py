#!/usr/bin/env python3
"""
Quick setup script for SecureChat.
This script generates certificates and sets up the basic environment.
"""
import os
import sys
import subprocess

def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"Running: {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def main():
    """Setup SecureChat environment."""
    print("SecureChat Quick Setup")
    print("=" * 30)
    
    # Check if we're in the right directory
    if not os.path.exists("app") or not os.path.exists("scripts"):
        print("Error: Please run this script from the securechat-skeleton-main directory")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs("certs", exist_ok=True)
    os.makedirs("transcripts", exist_ok=True)
    
    print("1. Generating Root CA certificate...")
    if not run_command('python scripts/gen_ca.py --name "FAST-NU Root CA"', "Generate CA"):
        print("Failed to generate CA certificate")
        sys.exit(1)
    
    print("\n2. Generating server certificate...")
    if not run_command('python scripts/gen_cert.py --cn server.local --out certs/server', "Generate server cert"):
        print("Failed to generate server certificate")
        sys.exit(1)
    
    print("\n3. Generating client certificate...")
    if not run_command('python scripts/gen_cert.py --cn client.local --out certs/client', "Generate client cert"):
        print("Failed to generate client certificate") 
        sys.exit(1)
    
    print("\n4. Testing basic functionality...")
    if not run_command('python test_implementation.py', "Run tests"):
        print("Some tests failed, but you can still try running the application")
    
    print("\n" + "=" * 50)
    print("🎉 Setup completed!")
    print("\nNext steps:")
    print("1. Set up MySQL database:")
    print("   docker run -d --name securechat-db \\")
    print("     -e MYSQL_ROOT_PASSWORD=rootpass \\")
    print("     -e MYSQL_DATABASE=securechat \\")
    print("     -e MYSQL_USER=scuser \\")
    print("     -e MYSQL_PASSWORD=scpass \\")
    print("     -p 3306:3306 mysql:8")
    print("")
    print("2. Initialize database:")
    print("   python -m app.storage.db --init")
    print("")
    print("3. Start the server:")
    print("   python -m app.server")
    print("")
    print("4. In another terminal, start the client:")
    print("   python -m app.client")
    print("")
    print("Generated certificates are in the 'certs/' directory.")
    print("IMPORTANT: Do not commit private keys to version control!")

if __name__ == "__main__":
    main()