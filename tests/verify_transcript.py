#!/usr/bin/env python3
"""
Simple Transcript Verification Utility
Verifies existing transcript files for non-repudiation testing
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.crypto.sign import rsa_verify_with_cert
from app.common.utils import b64d, sha256_hex


def load_transcript_entries(transcript_file):
    """Load transcript entries from file"""
    entries = []
    try:
        with open(transcript_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    entry = json.loads(line)
                    entries.append(entry)
    except Exception as e:
        print(f"Error loading transcript: {e}")
    return entries


def verify_message_signature(entry, client_cert_pem, server_cert_pem):
    """Verify signature of individual message"""
    try:
        # Reconstruct signed data
        data_to_verify = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}"
        signature = b64d(entry['signature'])
        
        # Determine which certificate to use based on direction
        if entry.get('direction') == 'sent':
            # Message sent by client
            cert_pem = client_cert_pem
            signer = "client"
        else:
            # Message sent by server  
            cert_pem = server_cert_pem
            signer = "server"
        
        # Verify signature
        is_valid = rsa_verify_with_cert(data_to_verify, signature, cert_pem)
        
        return {
            'seqno': entry['seqno'],
            'signer': signer,
            'valid': is_valid,
            'timestamp': entry['timestamp']
        }
        
    except Exception as e:
        return {
            'seqno': entry.get('seqno', 'unknown'),
            'signer': 'unknown',
            'valid': False,
            'error': str(e)
        }


def verify_receipt_signature(receipt_file, server_cert_pem, client_cert_pem):
    """Verify session receipt signature"""
    try:
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
        
        # Verify receipt signature with correct certificate based on who signed it
        transcript_hash = receipt['transcript_sha256']
        signature = b64d(receipt['sig'])
        
        # Use appropriate certificate based on who created the receipt
        if receipt.get('peer') == 'client':
            # Client-generated receipt, verify with client certificate
            cert_pem = client_cert_pem
            signer = "client"
        else:
            # Server-generated receipt, verify with server certificate
            cert_pem = server_cert_pem
            signer = "server"
        
        is_valid = rsa_verify_with_cert(transcript_hash, signature, cert_pem)
        
        return {
            'type': receipt.get('type'),
            'valid': is_valid,
            'signer': signer,
            'transcript_hash': transcript_hash,
            'first_seq': receipt.get('first_seq'),
            'last_seq': receipt.get('last_seq')
        }
        
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }


def compute_transcript_hash(entries):
    """Compute hash of transcript entries"""
    lines = []
    for entry in entries:
        line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry.get('peer_cert_fingerprint', '')}"
        lines.append(line)
    
    if not lines:
        return sha256_hex("")
    
    transcript_content = '\n'.join(sorted(lines))  # Sort for deterministic hash
    return sha256_hex(transcript_content)


def main():
    parser = argparse.ArgumentParser(description='Verify SecureChat transcript for non-repudiation')
    parser.add_argument('--transcript', required=True, help='Path to transcript file')
    parser.add_argument('--receipt', help='Path to session receipt file (optional)')
    parser.add_argument('--server-cert', default='certs/server-cert.pem', help='Server certificate file')
    parser.add_argument('--client-cert', default='certs/client-cert.pem', help='Client certificate file')
    parser.add_argument('--output', help='Output verification report to file')
    
    args = parser.parse_args()
    
    # Load certificates
    try:
        with open(args.server_cert, 'r') as f:
            server_cert_pem = f.read()
        with open(args.client_cert, 'r') as f:
            client_cert_pem = f.read()
    except Exception as e:
        print(f"Error loading certificates: {e}")
        return 1
    
    # Load transcript
    print(f"Loading transcript: {args.transcript}")
    entries = load_transcript_entries(args.transcript)
    
    if not entries:
        print("No transcript entries found!")
        return 1
    
    print(f"Found {len(entries)} transcript entries")
    
    # Verify each message
    print("\nVerifying message signatures...")
    print("-" * 60)
    
    verification_results = []
    valid_count = 0
    
    for entry in entries:
        result = verify_message_signature(entry, client_cert_pem, server_cert_pem)
        verification_results.append(result)
        
        status = "✓ VALID" if result['valid'] else "✗ INVALID"
        direction = entry.get('direction', 'unknown')
        
        print(f"Seq {result['seqno']:3d} ({direction:8s} by {result['signer']:6s}): {status}")
        
        if 'error' in result:
            print(f"         Error: {result['error']}")
        
        if result['valid']:
            valid_count += 1
    
    # Verify receipt if provided
    receipt_result = None
    if args.receipt:
        print(f"\nVerifying session receipt: {args.receipt}")
        print("-" * 60)
        
        receipt_result = verify_receipt_signature(args.receipt, server_cert_pem, client_cert_pem)
        
        if receipt_result['valid']:
            print("✓ Receipt signature VALID")
            print(f"  Transcript hash: {receipt_result['transcript_hash']}")
            print(f"  Sequence range: {receipt_result['first_seq']} - {receipt_result['last_seq']}")
        else:
            print("✗ Receipt signature INVALID")
            if 'error' in receipt_result:
                print(f"  Error: {receipt_result['error']}")
    
    # Compute transcript integrity hash
    print(f"\nTranscript Integrity:")
    print("-" * 60)
    computed_hash = compute_transcript_hash(entries)
    print(f"Computed hash: {computed_hash}")
    
    if args.receipt and receipt_result and receipt_result['valid']:
        expected_hash = receipt_result['transcript_hash']
        print(f"Receipt hash:  {expected_hash}")
        hash_match = computed_hash == expected_hash
        print(f"Hash match: {'✓ YES' if hash_match else '✗ NO'}")
    
    # Summary
    print(f"\nVerification Summary:")
    print("=" * 60)
    print(f"Total messages: {len(entries)}")
    print(f"Valid signatures: {valid_count}")
    print(f"Invalid signatures: {len(entries) - valid_count}")
    print(f"Success rate: {valid_count/len(entries)*100:.1f}%")
    
    if args.receipt:
        receipt_status = "VALID" if receipt_result and receipt_result['valid'] else "INVALID"
        print(f"Receipt signature: {receipt_status}")
    
    # Save report if requested
    if args.output:
        report = {
            'transcript_file': args.transcript,
            'receipt_file': args.receipt,
            'total_messages': len(entries),
            'valid_signatures': valid_count,
            'success_rate': valid_count/len(entries)*100,
            'message_results': verification_results,
            'receipt_result': receipt_result,
            'computed_hash': computed_hash
        }
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nDetailed report saved to: {args.output}")
    
    # Exit code reflects verification success
    all_valid = (valid_count == len(entries))
    receipt_valid = receipt_result['valid'] if receipt_result else True
    
    return 0 if (all_valid and receipt_valid) else 1


if __name__ == "__main__":
    sys.exit(main())