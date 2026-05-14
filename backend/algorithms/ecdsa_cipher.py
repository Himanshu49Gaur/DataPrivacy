import secrets
import hashlib
import base64


class ECDSACipher:
    """
    Implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA).

    This implementation utilizes the secp256k1 curve parameters and provides
    standard signing and verification capabilities.

    DISCLAIMER: While this mathematical implementation is correct for secp256k1
    ECDSA, production systems require constant-time operations and deterministic
    k generation (RFC 6979) to mitigate side-channel and nonce-reuse attacks.
    """

    # secp256k1 Curve Constants
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    G = (GX, GY)
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    @classmethod
    def _mod_inverse(cls, k: int, mod: int) -> int:
        """
        Compute the modular multiplicative inverse.

        Args:
            k: The integer to invert.
            mod: The modulus.

        Returns:
            The modular inverse of k modulo mod.
        """
        return pow(k, -1, mod)

    @classmethod
    def _add_points(
        cls, p1: tuple[int, int] | None, p2: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        """
        Perform elliptic curve point addition over the prime field P.

        Args:
            p1: The first point (x, y) or None for infinity.
            p2: The second point (x, y) or None for infinity.

        Returns:
            The resulting point (x, y) or None for infinity.
        """
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and (y1 != y2 or y1 == 0):
            return None

        if x1 == x2:
            # Point doubling
            lam = (3 * x1 * x1 + cls.A) * cls._mod_inverse(2 * y1, cls.P) % cls.P
        else:
            # Point addition
            lam = (y2 - y1) * cls._mod_inverse(x2 - x1, cls.P) % cls.P

        x3 = (lam * lam - x1 - x2) % cls.P
        y3 = (lam * (x1 - x3) - y1) % cls.P

        return (x3, y3)

    @classmethod
    def _scalar_mult(
        cls, k: int, point: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        """
        Perform scalar multiplication using the Double-and-Add algorithm.

        Args:
            k: The scalar factor.
            point: The base point (x, y).

        Returns:
            The resulting point (x, y) or None for infinity.
        """
        result = None
        addend = point

        k %= cls.N

        while k > 0:
            if k & 1:
                result = cls._add_points(result, addend)
            addend = cls._add_points(addend, addend)
            k >>= 1

        return result

    @classmethod
    def generate_keypair(cls) -> tuple[int, tuple[int, int]]:
        """
        Generate a private/public keypair for ECDSA.

        Returns:
            A tuple containing (private_key, public_key_point).
        """
        d = secrets.randbelow(cls.N - 1) + 1
        q = cls._scalar_mult(d, cls.G)
        return d, q  # type: ignore

    def sign(self, message: str, private_key: int) -> str:
        """
        Sign a message using the private key.

        Args:
            message: The UTF-8 string to sign.
            private_key: The local private key.

        Returns:
            Base64 encoded signature string (64 bytes raw).
        """
        z = int.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), "big")

        while True:
            k = secrets.randbelow(self.N - 1) + 1
            p1 = self._scalar_mult(k, self.G)
            if p1 is None:
                continue

            r = p1[0] % self.N
            if r == 0:
                continue

            k_inv = self._mod_inverse(k, self.N)
            s = (k_inv * (z + r * private_key)) % self.N
            if s == 0:
                continue

            signature_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            return base64.b64encode(signature_bytes).decode("utf-8")

    def verify(self, message: str, signature: str, public_key: tuple[int, int]) -> bool:
        """
        Verify an ECDSA signature.

        Args:
            message: The original UTF-8 message.
            signature: The Base64 encoded signature.
            public_key: The signer's public key point (x, y).

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            sig_bytes = base64.b64decode(signature)
            if len(sig_bytes) != 64:
                return False

            r = int.from_bytes(sig_bytes[:32], "big")
            s = int.from_bytes(sig_bytes[32:], "big")
        except Exception:
            return False

        if not (1 <= r < self.N and 1 <= s < self.N):
            return False

        z = int.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), "big")
        w = self._mod_inverse(s, self.N)
        u1 = (z * w) % self.N
        u2 = (r * w) % self.N

        p1 = self._add_points(
            self._scalar_mult(u1, self.G), self._scalar_mult(u2, public_key)
        )

        if p1 is None:
            return False

        return r == (p1[0] % self.N)
