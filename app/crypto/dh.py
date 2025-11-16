"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import secrets
from typing import Tuple
from ..common.utils import sha256_bytes, int_to_bytes


# Well-known DH parameters (1024-bit for simplicity - in practice use 2048+ bit)
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

DH_G = 2


class DHKeyExchange:
    """Diffie-Hellman key exchange implementation."""
    
    def __init__(self, p: int = None, g: int = None):
        """Initialize DH parameters."""
        self.p = p or DH_P
        self.g = g or DH_G
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self) -> Tuple[int, int]:
        """
        Generate DH keypair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        # Generate random private key
        self.private_key = secrets.randbelow(self.p - 2) + 1
        
        # Calculate public key: g^private mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        return self.private_key, self.public_key
    
    def compute_shared_secret(self, peer_public_key: int) -> int:
        """
        Compute shared secret from peer's public key.
        
        Args:
            peer_public_key: Peer's public key (g^b mod p)
            
        Returns:
            Shared secret (g^ab mod p)
        """
        if self.private_key is None:
            raise ValueError("Must generate keypair first")
        
        # Compute shared secret: peer_public^private mod p
        shared_secret = pow(peer_public_key, self.private_key, self.p)
        return shared_secret
    
    def derive_session_key(self, shared_secret: int) -> bytes:
        """
        Derive 16-byte AES session key from shared secret.
        
        K = Trunc16(SHA256(big-endian(Ks)))
        
        Args:
            shared_secret: DH shared secret as integer
            
        Returns:
            16-byte AES key
        """
        # Convert shared secret to big-endian bytes
        shared_secret_bytes = int_to_bytes(shared_secret)
        
        # Hash and truncate to 16 bytes
        hash_bytes = sha256_bytes(shared_secret_bytes)
        session_key = hash_bytes[:16]
        
        return session_key


def generate_dh_keypair(p: int = None, g: int = None) -> Tuple[int, int, int]:
    """
    Generate DH keypair with given parameters.
    
    Args:
        p: Prime modulus (default uses built-in)
        g: Generator (default uses built-in)
        
    Returns:
        Tuple of (private_key, public_key, p, g)
    """
    dh = DHKeyExchange(p, g)
    private_key, public_key = dh.generate_keypair()
    return private_key, public_key, dh.p, dh.g


def compute_dh_shared_secret(private_key: int, peer_public_key: int, p: int) -> int:
    """
    Compute DH shared secret.
    
    Args:
        private_key: Own private key
        peer_public_key: Peer's public key
        p: Prime modulus
        
    Returns:
        Shared secret
    """
    return pow(peer_public_key, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    
    Args:
        shared_secret: DH shared secret as integer
        
    Returns:
        16-byte AES key
    """
    # Convert to big-endian bytes
    shared_secret_bytes = int_to_bytes(shared_secret)
    
    # Hash and truncate to 16 bytes
    hash_bytes = sha256_bytes(shared_secret_bytes)
    return hash_bytes[:16]
