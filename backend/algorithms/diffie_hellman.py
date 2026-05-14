import secrets
import hashlib
import base64
from typing import Optional


class DiffieHellman:
    """Production-grade Diffie-Hellman Key Exchange implementation.

    This class provides methods for generating private and public keys and
    computing a shared secret using the Diffie-Hellman algorithm with a
    standard 2048-bit MODP Group prime (RFC 3526). It incorporates a
    SHA-256 Key Derivation Function (KDF) to ensure the resulting secret
    is suitable for use as a symmetric key.
    """

    DEFAULT_GENERATOR = 2
    RFC_3526_2048_PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
    )

    def __init__(self, prime: Optional[int] = None, generator: Optional[int] = None):
        """Initializes the Diffie-Hellman instance with a prime and generator.

        Args:
            prime: The large prime number for the group. Defaults to RFC 3526 2048-bit prime.
            generator: The generator for the group. Defaults to 2.

        Raises:
            TypeError: If prime or generator are not integers.
        """
        if prime is not None and not isinstance(prime, int):
            raise TypeError("Prime must be an integer.")
        if generator is not None and not isinstance(generator, int):
            raise TypeError("Generator must be an integer.")

        self.prime = prime if prime is not None else self.RFC_3526_2048_PRIME
        self.generator = generator if generator is not None else self.DEFAULT_GENERATOR

    def generate_private_key(self) -> int:
        """Generates a cryptographically secure private key.

        The key is strictly bounded between 1 and p-1 (exclusive of 1).

        Returns:
            A secure random integer to be used as a private key.
        """
        return secrets.randbelow(self.prime - 2) + 2

    def generate_public_key(self, private_key: int) -> int:
        """Computes the public key from a private key.

        Uses optimized modular exponentiation to compute g^a mod p.

        Args:
            private_key: The private integer used as the exponent.

        Returns:
            The computed public key.

        Raises:
            ValueError: If the private key is not within the valid range (1 < a < p).
            TypeError: If the private key is not an integer.
        """
        if not isinstance(private_key, int):
            raise TypeError("Private key must be an integer.")
        if not (1 < private_key < self.prime):
            raise ValueError("Private key must be strictly between 1 and p-1.")

        return pow(self.generator, private_key, self.prime)

    def compute_shared_secret(self, private_key: int, peer_public_key: int) -> str:
        """Computes the shared secret and derives a key using SHA-256.

        Accepts a private key and the peer's public key to compute the shared
        integer, which is then passed through a SHA-256 KDF and Base64 encoded.

        Args:
            private_key: The local private key.
            peer_public_key: The public key received from the peer.

        Returns:
            A Base64 encoded SHA-256 hash of the shared secret.

        Raises:
            TypeError: If inputs are not integers.
            ValueError: If peer_public_key is invalid.
        """
        if not isinstance(private_key, int) or not isinstance(peer_public_key, int):
            raise TypeError("Keys must be integers.")
        
        if not (1 < peer_public_key < self.prime):
            raise ValueError("Peer public key is out of valid range.")

        # Compute raw shared integer: s = B^a mod p
        shared_integer = pow(peer_public_key, private_key, self.prime)

        # Convert to bytes (256 bytes for 2048-bit prime)
        shared_bytes = shared_integer.to_bytes(256, byteorder="big")

        # Pass through SHA-256 KDF
        derived_key = hashlib.sha256(shared_bytes).digest()

        # Base64 encode for safe transmission
        return base64.b64encode(derived_key).decode("utf-8")
