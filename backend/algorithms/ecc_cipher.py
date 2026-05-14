import secrets
import hashlib
import base64


class ECCCipher:
    """
    Highly optimized implementation of ECC using the secp256k1 curve.

    DISCLAIMER: While the mathematical implementation is correct for secp256k1,
    writing custom ECC in Python is vulnerable to timing and side-channel
    attacks. This module is implemented exclusively as an advanced
    architectural primitive for educational demonstration.
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
    def _mod_inverse(cls, k: int, p: int) -> int:
        """
        Compute the modular multiplicative inverse.

        Args:
            k: The integer to invert.
            p: The modulus.

        Returns:
            The modular inverse of k modulo p.

        Raises:
            ZeroDivisionError: If the modular inverse does not exist.
        """
        try:
            return pow(k, -1, p)
        except ValueError:
            raise ZeroDivisionError("Modular inverse does not exist")

    @classmethod
    def _add_points(
        cls, p1: tuple[int, int] | None, p2: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        """
        Perform elliptic curve point addition over the finite field P.

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
            lam = (3 * x1 * x1 + cls.A) * cls._mod_inverse(2 * y1, cls.P) % cls.P
        else:
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
            The resulting point (x, y).
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
        Generate a private/public keypair.

        Returns:
            A tuple containing (private_key, public_key_point).
        """
        d = secrets.randbelow(cls.N - 1) + 1
        q = cls._scalar_mult(d, cls.G)
        return d, q  # type: ignore

    def compute_shared_secret(
        self, private_key: int, peer_public_key: tuple[int, int]
    ) -> str:
        """
        Compute a shared secret using ECDH.

        Args:
            private_key: The local private key.
            peer_public_key: The remote public key point (x, y).

        Returns:
            The SHA-256 hashed shared secret, Base64 encoded.

        Raises:
            ValueError: If the peer_public_key is invalid.
        """
        shared_point = self._scalar_mult(private_key, peer_public_key)

        if shared_point is None:
            raise ValueError("Invalid shared secret calculation (infinity point)")

        x_coordinate = shared_point[0]
        x_bytes = x_coordinate.to_bytes(32, "big")

        shared_hash = hashlib.sha256(x_bytes).digest()
        return base64.b64encode(shared_hash).decode("utf-8")
