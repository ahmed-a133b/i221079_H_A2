"""Append-only transcript + TranscriptHash helpers."""
import os
import json
from typing import List, Dict, Any, Optional
from ..common.utils import sha256_hex, now_ms


class TranscriptManager:
    """Manages append-only transcript for non-repudiation."""
    
    def __init__(self, filepath: str):
        """
        Initialize transcript manager.
        
        Args:
            filepath: Path to transcript file
        """
        self.filepath = filepath
        self.entries = []
        
        # Create directory if it doesn't exist
        dir_path = os.path.dirname(filepath)
        if dir_path:  # Only create directory if there is one
            os.makedirs(dir_path, exist_ok=True)
        
        # Load existing entries
        self._load_transcript()
    

    
    def _load_transcript(self):
        """Load existing transcript entries from file."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entry = json.loads(line)
                            self.entries.append(entry)
            except Exception as e:
                print(f"Warning: Could not load transcript from {self.filepath}: {e}")
    
    def add_message(self, seqno: int, timestamp: int, ciphertext: str, 
                   signature: str, peer_cert_fingerprint: str, 
                   direction: str = "sent") -> None:
        """
        Add a message to the transcript.
        
        Args:
            seqno: Sequence number
            timestamp: Timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer certificate
            direction: "sent" or "received"
        """
        entry = {
            "seqno": seqno,
            "timestamp": timestamp,
            "ciphertext": ciphertext,
            "signature": signature,
            "peer_cert_fingerprint": peer_cert_fingerprint,
            "direction": direction
        }
        
        # Append to in-memory list
        self.entries.append(entry)
        
        # Append to file immediately for persistence
        with open(self.filepath, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    
    def get_transcript_lines(self) -> List[str]:
        """
        Get transcript as list of formatted lines for hashing.
        
        Returns:
            List of transcript lines in format: "seqno|timestamp|ciphertext|signature|peer_cert_fingerprint"
        """
        lines = []
        for entry in self.entries:
            line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry['peer_cert_fingerprint']}"
            lines.append(line)
        return lines
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of the entire transcript.
        
        Returns:
            Hex-encoded SHA-256 hash of concatenated transcript lines
        """
        lines = self.get_transcript_lines()
        
        if not lines:
            return sha256_hex("")
        
        # Concatenate all lines
        transcript_content = '\n'.join(lines)
        
        # Return SHA-256 hash
        return sha256_hex(transcript_content)
    
    def get_sequence_range(self) -> tuple[int, int]:
        """
        Get the first and last sequence numbers in the transcript.
        
        Returns:
            Tuple of (first_seq, last_seq)
        """
        if not self.entries:
            return 0, 0
        
        first_seq = min(entry['seqno'] for entry in self.entries)
        last_seq = max(entry['seqno'] for entry in self.entries)
        
        return first_seq, last_seq
    
    def export_transcript(self, output_path: str) -> None:
        """
        Export transcript to a file for verification.
        
        Args:
            output_path: Path to export file
        """
        lines = self.get_transcript_lines()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Transcript Export\n")
            f.write("# Format: seqno|timestamp|ciphertext|signature|peer_cert_fingerprint\n")
            f.write("\n")
            
            for line in lines:
                f.write(line + '\n')
    
    def verify_transcript_integrity(self, expected_hash: str) -> bool:
        """
        Verify transcript integrity against expected hash.
        
        Args:
            expected_hash: Expected SHA-256 hash
            
        Returns:
            True if transcript hash matches expected hash
        """
        actual_hash = self.compute_transcript_hash()
        return actual_hash == expected_hash
    
    def get_message_count(self) -> int:
        """Get total number of messages in transcript."""
        return len(self.entries)
    
    def get_entries_by_direction(self, direction: str) -> List[Dict[str, Any]]:
        """
        Get entries filtered by direction.
        
        Args:
            direction: "sent" or "received"
            
        Returns:
            List of entries with specified direction
        """
        return [entry for entry in self.entries if entry.get('direction') == direction]
    
    def get_latest_sequence_number(self) -> int:
        """
        Get the latest sequence number in the transcript.
        
        Returns:
            Latest sequence number, or 0 if no entries
        """
        if not self.entries:
            return 0
        
        return max(entry['seqno'] for entry in self.entries)


def create_session_receipt(transcript: TranscriptManager, peer_type: str, 
                          private_key_pem: str) -> Dict[str, Any]:
    """
    Create a session receipt for non-repudiation.
    
    Args:
        transcript: TranscriptManager instance
        peer_type: "client" or "server"
        private_key_pem: RSA private key in PEM format
        
    Returns:
        Session receipt dictionary
    """
    from ..crypto.sign import rsa_sign
    from ..common.utils import b64e
    
    # Get sequence range
    first_seq, last_seq = transcript.get_sequence_range()
    
    # Compute transcript hash
    transcript_hash = transcript.compute_transcript_hash()
    
    # Sign the transcript hash
    signature = rsa_sign(transcript_hash, private_key_pem)
    
    # Create receipt
    receipt = {
        "type": "receipt",
        "peer": peer_type,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": b64e(signature)
    }
    
    return receipt


def verify_session_receipt(receipt: Dict[str, Any], transcript_lines: List[str], 
                          cert_pem: str) -> bool:
    """
    Verify a session receipt.
    
    Args:
        receipt: Session receipt dictionary
        transcript_lines: List of transcript lines for verification
        cert_pem: Certificate for signature verification
        
    Returns:
        True if receipt is valid
    """
    from ..crypto.sign import rsa_verify_with_cert
    from ..common.utils import b64d, sha256_hex
    
    try:
        # Recompute transcript hash
        transcript_content = '\n'.join(transcript_lines) if transcript_lines else ""
        computed_hash = sha256_hex(transcript_content)
        
        # Check if hash matches
        if computed_hash != receipt['transcript_sha256']:
            return False
        
        # Verify signature
        signature = b64d(receipt['sig'])
        return rsa_verify_with_cert(receipt['transcript_sha256'], signature, cert_pem)
        
    except Exception:
        return False
