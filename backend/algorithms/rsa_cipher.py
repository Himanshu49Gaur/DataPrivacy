import secrets
import base64
from typing import Tuple


class RSACipher:
    """Foundational RSA primitive for educational and architectural demonstration.

    Disclaimer: This implementation is "Textbook RSA" and lacks OAEP padding.
    It is intended strictly as a foundational cryptographic primitive for
    architectural demonstration and educational purposes.
    """

    @classmethod
    def _miller_rabin(cls, n: int, k: int = 40) -> bool:
        """Performs the Miller-Rabin primality test.

        Args:
            n: The integer to test for primality.
            k: The number of testing rounds (default 40 for high confidence).

        Returns:
            True if n is probably prime, False if n is definitely composite.
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n - 1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = secrets.randbelow(n - 4) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @classmethod
    def _generate_prime(cls, bits: int) -> int:
        """Generates a cryptographically secure prime integer.

        Args:
            bits: The exact bit length of the prime to generate.

        Returns:
            A cryptographically secure prime integer.
        """
        while True:
            # Force top two bits and bottom bit to 1
            p = secrets.randbits(bits)
            p |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
            if cls._miller_rabin(p):
                return p

    @classmethod
    def generate_keypair(cls, keysize: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Generates an RSA public and private keypair.

        Args:
            keysize: The total bit length of the modulus n (default 2048).

        Returns:
            A tuple containing ((n, e), (n, d)).
        """
        p = cls._generate_prime(keysize // 2)
        q = cls._generate_prime(keysize // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        return ((n, e), (n, d))

    def encrypt(self, plaintext: str, public_key: Tuple[int, int]) -> str:
        """Encrypts a string using an RSA public key.

        Args:
            plaintext: The UTF-8 string to encrypt.
            public_key: A tuple containing (n, e).

        Returns:
            A Base64 encoded UTF-8 string representing the ciphertext.

        Raises:
            ValueError: If the plaintext integer exceeds the RSA block limit.
        """
        n, e = public_key
        data = plaintext.encode("utf-8")
        m = int.from_bytes(data, "big")

        if m >= n:
            raise ValueError("Payload exceeds RSA block limit (modulus n).")

        c = pow(m, e, n)
        # Calculate minimum bytes needed to represent c
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, "big")
        return base64.b64encode(c_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, private_key: Tuple[int, int]) -> str:
        """Decrypts a Base64 encoded string using an RSA private key.

        Args:
            ciphertext: The Base64 encoded ciphertext string.
            private_key: A tuple containing (n, d).

        Returns:
            The decrypted UTF-8 plaintext string.
        """
        n, d = private_key
        c_bytes = base64.b64decode(ciphertext)
        c = int.from_bytes(c_bytes, "big")

        m = pow(c, d, n)
        m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        return m_bytes.decode("utf-8")
