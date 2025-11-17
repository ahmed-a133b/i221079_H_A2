#!/usr/bin/env python3
"""
SecureChat Security Test Launcher
Runs comprehensive security tests based on configuration files
"""

import os
import sys
import yaml
import json
import time
import signal
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class TestLauncher:
    
    
    def __init__(self, config_path: str = "tests/test_config.yaml"):
        """Initialize test launcher with configuration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.active_processes = []
        self.test_results = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load test configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    def _setup_test_environment(self):
        """Setup test environment (database, certificates, etc.)"""
        print("Setting up test environment...")
        
        # Reset database if configured
        if self.config['global_config']['database']['reset_before_test']:
            try:
                subprocess.run([
                    sys.executable, "-m", "app.storage.db", "--init"
                ], cwd=project_root, check=True)
                print("✓ Database reset complete")
            except subprocess.CalledProcessError as e:
                print(f"✗ Database reset failed: {e}")
        
        # Generate certificates if they don't exist
        self._ensure_certificates_exist()
        
        # Create test directories
        for test_name, test_config in self.config['test_scenarios'].items():
            if 'output_dir' in test_config:
                os.makedirs(test_config['output_dir'], exist_ok=True)
        
        # Create packet capture directory
        packet_dir = self.config['global_config']['logging']['packet_dir']
        os.makedirs(packet_dir, exist_ok=True)
        
        print("✓ Test environment ready")
    
    def _ensure_certificates_exist(self):
        """Ensure all required certificates exist for testing"""
        cert_files = [
            'certs/ca-cert.pem',
            'certs/server-cert.pem', 
            'certs/server-key.pem',
            'certs/client-cert.pem',
            'certs/client-key.pem'
        ]
        
        missing_certs = [cert for cert in cert_files if not os.path.exists(os.path.join(project_root, cert))]
        
        if missing_certs:
            print("Missing certificates detected. Generating...")
            
            # Generate main certificates first
            try:
                subprocess.run([
                    sys.executable, "scripts/gen_ca.py"
                ], cwd=project_root, check=True)
                
                subprocess.run([
                    sys.executable, "scripts/gen_cert.py", 
                    "--cert-type", "server", "--cn", "server.local"
                ], cwd=project_root, check=True)
                
                subprocess.run([
                    sys.executable, "scripts/gen_cert.py",
                    "--cert-type", "client", "--cn", "client.local" 
                ], cwd=project_root, check=True)
                
                print("✓ Main certificates generated")
                
            except subprocess.CalledProcessError as e:
                print(f"✗ Certificate generation failed: {e}")
        
        # Generate invalid certificates for testing
        try:
            subprocess.run([
                sys.executable, "tests/generate_invalid_certs.py"
            ], cwd=project_root, check=True)
            print("✓ Invalid test certificates generated")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠ Invalid certificate generation failed: {e}")
            print("  Tests will continue with available certificates")
    
    def _start_server(self, server_config: Dict[str, Any], test_name: str) -> subprocess.Popen:
        """Start server with specific configuration"""
        print(f"Starting server for {test_name}...")
        
        # Set environment variables
        env = os.environ.copy()
        env.update({
            'SERVER_HOST': server_config['host'],
            'SERVER_PORT': str(server_config['port']),
            'SERVER_CERT_PATH': server_config['cert_path'],
            'SERVER_KEY_PATH': server_config['key_path'],
            'CA_CERT_PATH': server_config['ca_path']
        })
        
        # Start server process
        process = subprocess.Popen([
            sys.executable, "-m", "app.server"
        ], cwd=project_root, env=env, 
           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
           text=True, bufsize=1)
        
        # Wait longer for server to start and verify it's running
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"✗ Server failed to start. Output: {stdout}")
            raise RuntimeError(f"Server process exited with code {process.returncode}")
        
        self.active_processes.append(process)
        print(f"✓ Server started on {server_config['host']}:{server_config['port']}")
        return process
    
    def _cleanup_processes(self):
        """Clean up all active processes"""
        for process in self.active_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception:
                pass
        self.active_processes.clear()
    
    def run_invalid_certificate_test(self) -> Dict[str, Any]:
        """Run invalid certificate test scenario"""
        test_config = self.config['test_scenarios']['invalid_certificate']
        print(f"\n=== {test_config['name']} ===")
        print(test_config['description'])
        
        results = {'test_name': test_config['name'], 'results': []}
        
        # Start server
        server_process = self._start_server(test_config['server_config'], 'invalid_cert')
        
        try:
            for client_config in test_config['client_configs']:
                print(f"\nTesting {client_config['name']}...")
                
                # Run client with invalid certificate
                result = self._run_client_test(
                    test_config['server_config'],
                    client_config,
                    test_type="invalid_cert"
                )
                
                result['expected'] = client_config['expected_result']
                result['test_case'] = client_config['name']
                results['results'].append(result)
                
                print(f"Result: {result['status']} (expected: {client_config['expected_result']})")
        
        finally:
            server_process.terminate()
            
        return results
    
    def run_tampering_test(self) -> Dict[str, Any]:
        """Run message tampering test scenario"""
        test_config = self.config['test_scenarios']['tampering_test']
        print(f"\n=== {test_config['name']} ===")
        print(test_config['description'])
        
        results = {'test_name': test_config['name'], 'results': []}
        
        # Start server
        server_process = self._start_server(test_config['server_config'], 'tampering')
        
        try:
            # Create tampering test client
            from tests.tampering_client import TamperingTestClient
            
            client = TamperingTestClient(
                host=test_config['server_config']['host'],
                port=test_config['server_config']['port'],
                client_config=test_config['client_config']
            )
            
            # Test each tampering pattern
            for pattern in test_config['tampering_patterns']:
                for message in test_config['test_messages']:
                    print(f"Testing tampering pattern: {pattern}")
                    
                    result = client.test_message_tampering(message, pattern)
                    result['expected'] = test_config['expected_result']
                    results['results'].append(result)
                    
                    print(f"Result: {result['status']}")
        
        except Exception as e:
            print(f"Tampering test error: {e}")
            results['error'] = str(e)
        
        finally:
            server_process.terminate()
            
        return results
    
    def run_replay_attack_test(self) -> Dict[str, Any]:
        """Run replay attack test scenario"""
        test_config = self.config['test_scenarios']['replay_attack']
        print(f"\n=== {test_config['name']} ===")
        print(test_config['description'])
        
        results = {'test_name': test_config['name'], 'results': []}
        
        # Start server
        server_process = self._start_server(test_config['server_config'], 'replay')
        
        try:
            from tests.replay_client import ReplayTestClient
            
            client = ReplayTestClient(
                host=test_config['server_config']['host'],
                port=test_config['server_config']['port'],
                client_config=test_config['client_config']
            )
            
            # Send initial messages first
            print("Sending initial messages...")
            initial_results = client.send_initial_messages(
                test_config['test_scenario']['initial_messages']
            )
            
            if initial_results:  # Only proceed if initial messages were sent
                # Attempt replay attacks
                print("Attempting replay attacks...")
                for seq_no in test_config['test_scenario']['replay_sequences']:
                    result = client.replay_message(seq_no)
                    result['expected'] = test_config['expected_result']
                    results['results'].append(result)
                    
                    print(f"Replay seq {seq_no}: {result['status']}")
                    time.sleep(test_config['test_scenario']['replay_delay'])
            else:
                results['error'] = "Failed to send initial messages for replay test"
        
        except Exception as e:
            print(f"Replay test error: {e}")
            results['error'] = str(e)
        
        finally:
            server_process.terminate()
            
        return results
    
    def run_non_repudiation_test(self) -> Dict[str, Any]:
        """Run non-repudiation verification test"""
        test_config = self.config['test_scenarios']['non_repudiation']
        print(f"\n=== {test_config['name']} ===")
        print(test_config['description'])
        
        results = {'test_name': test_config['name'], 'results': []}
        
        # Start server
        server_process = self._start_server(test_config['server_config'], 'non_repudiation')
        
        try:
            from tests.verification_client import VerificationTestClient
            
            client = VerificationTestClient(
                host=test_config['server_config']['host'],
                port=test_config['server_config']['port'],
                client_config=test_config['client_config'],
                output_dir=test_config['output_dir']
            )
            
            # Generate messages and transcript
            print("Generating test session...")
            session_result = client.generate_test_session(
                test_config['verification_tests']['message_count']
            )
            
            # Export transcript and receipt
            if test_config['verification_tests']['transcript_export']:
                transcript_path = client.export_transcript()
                results['transcript_path'] = transcript_path
                
            if test_config['verification_tests']['receipt_export']:
                receipt_path = client.export_receipt()
                results['receipt_path'] = receipt_path
            
            # Run offline verification
            print("Running offline verification...")
            verification_results = client.run_offline_verification()
            results['verification'] = verification_results
            
            # Test tampering detection
            print("Testing tamper detection...")
            tamper_results = client.test_tamper_detection(
                test_config['verification_tests']['tamper_tests']
            )
            results['tamper_detection'] = tamper_results
        
        except Exception as e:
            print(f"Non-repudiation test error: {e}")
            results['error'] = str(e)
        
        finally:
            server_process.terminate()
            
        return results
    
    def _run_client_test(self, server_config: Dict, client_config: Dict, 
                        test_type: str) -> Dict[str, Any]:
        """Run a basic client test for certificate validation"""
        result = {
            'status': 'UNKNOWN',
            'timestamp': time.time(),
            'test_type': test_type
        }
        
        try:
            # Simple client that tests certificate validation
            import socket
            import json
            import secrets
            from app.common.protocol import HelloMessage
            from app.common.utils import b64e
            
            # Load client certificate
            try:
                with open(client_config['cert_path'], 'r') as f:
                    client_cert = f.read()
            except Exception as e:
                result['status'] = 'ERROR'
                result['error'] = f"Failed to load certificate: {e}"
                return result
            
            # Connect to server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            
            try:
                sock.connect((server_config['host'], server_config['port']))
                
                # Send hello with potentially invalid certificate
                hello = HelloMessage(
                    client_cert=client_cert, 
                    nonce=b64e(secrets.token_bytes(16))
                )
                
                # Send message
                message = hello.model_dump()
                json_data = json.dumps(message)
                message_bytes = json_data.encode('utf-8')
                
                length = len(message_bytes)
                sock.send(length.to_bytes(4, 'big'))
                sock.send(message_bytes)
                
                # Receive response
                length_bytes = sock.recv(4)
                if length_bytes:
                    length = int.from_bytes(length_bytes, 'big')
                    response_bytes = sock.recv(length)
                    response = json.loads(response_bytes.decode('utf-8'))
                    
                    # Check server response
                    if response.get('status') == 'bad_cert':
                        result['status'] = 'BAD_CERT'
                    elif response.get('type') == 'server_hello':
                        result['status'] = 'ACCEPTED'  # Certificate was accepted
                    else:
                        result['status'] = response.get('status', 'UNKNOWN')
                        
                    result['server_response'] = response
                else:
                    result['status'] = 'NO_RESPONSE'
                    
            except socket.timeout:
                result['status'] = 'TIMEOUT'
            except Exception as e:
                result['status'] = 'ERROR' 
                result['error'] = str(e)
            finally:
                sock.close()
                
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all configured test scenarios"""
        print("Starting SecureChat Security Test Suite")
        print("=" * 50)
        
        self._setup_test_environment()
        
        all_results = {
            'timestamp': time.time(),
            'config_file': self.config_path,
            'tests': {}
        }
        
        try:
            # Run each test scenario
            all_results['tests']['invalid_certificate'] = self.run_invalid_certificate_test()
            all_results['tests']['tampering'] = self.run_tampering_test()
            
        except KeyboardInterrupt:
            print("\nTest suite interrupted by user")
        except Exception as e:
            print(f"Test suite error: {e}")
            all_results['error'] = str(e)
        finally:
            self._cleanup_processes()
        
        return all_results
    
    def run_single_test(self, test_name: str) -> Dict[str, Any]:
        """Run a single test scenario"""
        if test_name not in self.config['test_scenarios']:
            raise ValueError(f"Unknown test: {test_name}")
        
        self._setup_test_environment()
        
        try:
            if test_name == 'invalid_certificate':
                return self.run_invalid_certificate_test()
            elif test_name == 'tampering_test':
                return self.run_tampering_test()
        finally:
            self._cleanup_processes()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureChat Security Test Launcher')
    parser.add_argument('--config', default='tests/test_config.yaml',
                       help='Test configuration file')
    parser.add_argument('--test', choices=['invalid_certificate', 'tampering_test'],
                       help='Run specific test (default: run all)')
    parser.add_argument('--output', default='tests/test_results.json',
                       help='Output file for test results')
    
    args = parser.parse_args()
    
    # Create test launcher
    launcher = TestLauncher(args.config)
    
    # Run tests
    if args.test:
        results = launcher.run_single_test(args.test)
    else:
        results = launcher.run_all_tests()
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nTest results saved to: {args.output}")
    
    # Print summary
    print("\nTest Summary:")
    print("=" * 30)
    if 'tests' in results:
        for test_name, test_result in results['tests'].items():
            status = "PASS" if 'error' not in test_result else "FAIL"
            print(f"{test_name}: {status}")
    
    # Print manual testing guidance
    print("\nFor additional security testing:")
    print("- Replay Attack Testing: See tests/MANUAL_TESTING_GUIDE.md")
    print("- Non-Repudiation: Use tests/verify_transcript.py with existing transcripts")
    
    return results


if __name__ == "__main__":
    main()