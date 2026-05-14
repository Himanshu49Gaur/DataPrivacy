import secrets
import base64
from typing import Tuple, Optional


class ElGamalCipher:
    """Advanced cryptographic primitive for educational and architectural demonstration.

    Disclaimer: This implementation is "Textbook ElGamal" (lacking CCA security
    padding such as OAEP or similar) and is strictly an advanced cryptographic
    primitive for educational and architectural demonstration.

    Attributes:
        DEFAULT_GENERATOR (int): Standard generator value (2).
        RFC_3526_2048_PRIME (int): The 2048-bit MODP Group prime from RFC 3526.
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
        """Initializes the ElGamal cipher instance.

        Args:
            prime: The large prime number for the group. Defaults to RFC 3526 2048-bit prime.
            generator: The generator for the group. Defaults to 2.
        """
        self.prime = prime if prime is not None else self.RFC_3526_2048_PRIME
        self.generator = generator if generator is not None else self.DEFAULT_GENERATOR

    def generate_keypair(self) -> Tuple[Tuple[int, int, int], Tuple[int, int, int]]:
        """Generates an ElGamal public and private keypair.

        Returns:
            A tuple containing (public_key, private_key).
            public_key: (p, g, y)
            private_key: (p, g, x)
        """
        x = secrets.randbelow(self.prime - 2) + 2
        y = pow(self.generator, x, self.prime)
        return (self.prime, self.generator, y), (self.prime, self.generator, x)

    def encrypt(self, plaintext: str, public_key: Tuple[int, int, int]) -> str:
        """Encrypts a string using an ElGamal public key.

        Args:
            plaintext: The UTF-8 string to encrypt.
            public_key: A tuple containing (p, g, y).

        Returns:
            A Base64 encoded UTF-8 string representing the ciphertext (c1:c2).

        Raises:
            ValueError: If the plaintext integer exceeds the group prime p.
        """
        p, g, y = public_key
        data = plaintext.encode("utf-8")
        m = int.from_bytes(data, "big")

        if m >= p:
            raise ValueError("Payload exceeds ElGamal block limit (prime p).")

        k = secrets.randbelow(p - 2) + 2
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p

        serialized = f"{hex(c1)}:{hex(c2)}"
        return base64.b64encode(serialized.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str, private_key: Tuple[int, int, int]) -> str:
        """Decrypts a Base64 encoded string using an ElGamal private key.

        Args:
            ciphertext: The Base64 encoded ciphertext string (c1:c2).
            private_key: A tuple containing (p, g, x).

        Returns:
            The decrypted UTF-8 plaintext string.
        """
        p, g, x = private_key
        decoded = base64.b64decode(ciphertext).decode("utf-8")
        c1_str, c2_str = decoded.split(":")
        c1 = int(c1_str, 16)
        c2 = int(c2_str, 16)

        s = pow(c1, x, p)
        s_inv = pow(s, -1, p)
        m = (c2 * s_inv) % p

        m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        return m_bytes.decode("utf-8")
