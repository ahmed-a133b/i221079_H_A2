#!/usr/bin/env python3
"""
Offline verification script for non-repudiation evidence.
This script can verify exported transcript evidence independently.
"""

import json
import sys
import os
from datetime import datetime

# Add app modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from crypto.sign import rsa_verify_with_cert
from common.utils import sha256_hex


def verify_evidence_file(evidence_file):
    """Verify exported non-repudiation evidence."""
    print("Offline Non-Repudiation Verification")
    print("=" * 40)
    
    try:
        with open(evidence_file, 'r') as f:
            evidence = json.load(f)
    except Exception as e:
        print(f"Error loading evidence file: {e}")
        return False
    
    messages = evidence.get("messages", [])
    transcript_hash = evidence.get("transcript_hash", "")
    receipt = evidence.get("session_receipt", {})
    certificates = evidence.get("certificates", {})
    
    print(f"Evidence file: {evidence_file}")
    print(f"Messages to verify: {len(messages)}")
    print(f"Transcript hash: {transcript_hash}")
    print()
    
    # Verify each message
    all_valid = True
    for i, message in enumerate(messages):
        sender = message["sender"]
        cert = certificates.get(sender)
        
        if not cert:
            print(f"✗ Message {i+1}: No certificate for sender '{sender}'")
            all_valid = False
            continue
        
        # Reconstruct message data for verification
        verify_data = {
            "sender": message["sender"],
            "recipient": message["recipient"],
            "message": message["message"],
            "seqno": message["seqno"],
            "timestamp": message["timestamp"]
        }
        
        # Compute hash
        verify_json = json.dumps(verify_data, sort_keys=True)
        verify_hash = sha256_hex(verify_json)
        
        # Verify signature
        try:
            if rsa_verify_with_cert(verify_hash, message["signature"], cert):
                print(f"✓ Message {i+1} ({sender}): AUTHENTIC")
            else:
                print(f"✗ Message {i+1} ({sender}): SIGNATURE INVALID")
                all_valid = False
        except Exception as e:
            print(f"✗ Message {i+1} ({sender}): Verification failed - {e}")
            all_valid = False
    
    # Verify session receipt
    print()
    print("Verifying session receipt...")
    
    if receipt and certificates.get(receipt["signer"]):
        receipt_data = {
            "session_id": receipt["session_id"],
            "transcript_hash": receipt["transcript_hash"],
            "timestamp": receipt["timestamp"],
            "signer": receipt["signer"]
        }
        
        receipt_json = json.dumps(receipt_data, sort_keys=True)
        receipt_hash = sha256_hex(receipt_json)
        
        try:
            signer_cert = certificates[receipt["signer"]]
            if rsa_verify_with_cert(receipt_hash, receipt["signature"], signer_cert):
                print(f"✓ Session receipt: AUTHENTIC (signed by {receipt['signer']})")
            else:
                print(f"✗ Session receipt: SIGNATURE INVALID")
                all_valid = False
        except Exception as e:
            print(f"✗ Session receipt: Verification failed - {e}")
            all_valid = False
    else:
        print("✗ Session receipt: Missing or invalid data")
        all_valid = False
    
    print()
    if all_valid:
        print("🔒 VERIFICATION PASSED: All messages and receipt are authentic")
        print("   No evidence of tampering detected.")
    else:
        print("❌ VERIFICATION FAILED: Some signatures are invalid")
        print("   Evidence may have been tampered with.")
    
    return all_valid


if __name__ == "__main__":
    evidence_file = "non_repudiation_evidence.json"
    if len(sys.argv) > 1:
        evidence_file = sys.argv[1]
    
    if not os.path.exists(evidence_file):
        print(f"Evidence file '{evidence_file}' not found.")
        print("Run the security test suite first to generate evidence.")
        sys.exit(1)
    
    verify_evidence_file(evidence_file)