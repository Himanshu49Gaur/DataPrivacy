import secrets
import hashlib
import base64


class RabinCipher:
    """
    Implementation of the Rabin Public-Key Cryptosystem.

    This implementation utilizes deterministic redundancy padding (checksums)
    to resolve the four-fold root ambiguity inherent in Rabin decryption.
    It uses Blum primes (p ≡ 3 mod 4) to ensure efficient square root
    extraction modulo p and q.

    DISCLAIMER: This module is designed as an advanced cryptographic primitive,
    intended for educational and architectural demonstration.
    """

    @classmethod
    def _miller_rabin(cls, n: int, k: int = 40) -> bool:
        """
        Perform the Miller-Rabin primality test.

        Args:
            n: The integer to test for primality.
            k: The number of testing rounds (default 40).

        Returns:
            True if n is probably prime, False otherwise.
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
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
    def _generate_blum_prime(cls, bits: int) -> int:
        """
        Generate a Blum prime p where p ≡ 3 mod 4.

        Args:
            bits: The desired bit length of the prime.

        Returns:
            A Blum prime p.
        """
        while True:
            candidate = secrets.randbits(bits)
            # Force top two bits and bottom bit to 1
            candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
            if candidate % 4 == 3 and cls._miller_rabin(candidate):
                return candidate

    @classmethod
    def _extended_gcd(cls, a: int, b: int) -> tuple[int, int, int]:
        """
        Implement the Extended Euclidean Algorithm.

        Args:
            a: First integer.
            b: Second integer.

        Returns:
            A tuple (gcd, x, y) such that a*x + b*y = gcd.
        """
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t

    @classmethod
    def generate_keypair(cls, keysize: int = 1024) -> tuple[int, tuple[int, int]]:
        """
        Generate a Rabin keypair.

        Args:
            keysize: The desired bit length of the modulus n.

        Returns:
            A tuple containing (public_key_n, private_key_pq).
        """
        p = cls._generate_blum_prime(keysize // 2)
        q = cls._generate_blum_prime(keysize // 2)
        while p == q:
            q = cls._generate_blum_prime(keysize // 2)
        return p * q, (p, q)

    def encrypt(self, plaintext: str, public_key: int) -> str:
        """
        Encrypt a message using the Rabin cryptosystem.

        Args:
            plaintext: The UTF-8 string to encrypt.
            public_key: The modulus n.

        Returns:
            Base64 encoded ciphertext string.

        Raises:
            ValueError: If the message (with padding) exceeds the modulus size.
        """
        plaintext_bytes = plaintext.encode("utf-8")
        checksum = hashlib.sha256(plaintext_bytes).digest()[:4]
        padded_data = plaintext_bytes + checksum
        m = int.from_bytes(padded_data, "big")

        if m >= public_key:
            raise ValueError("Payload exceeds Rabin block limit")

        c = pow(m, 2, public_key)
        # Calculate required bytes for n to ensure consistent padding/unpadding
        n_bytes = (public_key.bit_length() + 7) // 8
        c_bytes = c.to_bytes(n_bytes, "big")
        return base64.b64encode(c_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, private_key: tuple[int, int]) -> str:
        """
        Decrypt a Rabin-encrypted message using CRT and root disambiguation.

        Args:
            ciphertext: The Base64 encoded ciphertext.
            private_key: A tuple containing (p, q).

        Returns:
            The decrypted UTF-8 plaintext string.

        Raises:
            ValueError: If no valid root passes the checksum verification.
        """
        c = int.from_bytes(base64.b64decode(ciphertext), "big")
        p, q = private_key
        n = p * q

        # Compute principal square roots modulo p and q
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)

        # Use Extended GCD to find coefficients yp, yq such that yp*p + yq*q = 1
        _, yp, yq = self._extended_gcd(p, q)

        # Compute the four candidate roots modulo n using CRT
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        for root in [r1, r2, r3, r4]:
            # Convert root to bytes
            # n_bytes = (n.bit_length() + 7) // 8
            # We use a more flexible conversion for variable length data
            try:
                # Calculate necessary byte length for this specific root
                root_len = (root.bit_length() + 7) // 8
                data = root.to_bytes(root_len, "big")

                if len(data) < 4:
                    continue

                candidate_plaintext = data[:-4]
                candidate_checksum = data[-4:]

                expected_checksum = hashlib.sha256(candidate_plaintext).digest()[:4]

                if candidate_checksum == expected_checksum:
                    return candidate_plaintext.decode("utf-8")
            except (UnicodeDecodeError, OverflowError):
                continue

        raise ValueError("Decryption failed: Ciphertext corruption or invalid key")
