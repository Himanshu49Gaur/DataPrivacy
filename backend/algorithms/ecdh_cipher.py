import secrets
import hashlib
import base64


class ECDHCipher:
    """
    Implementation of Elliptic-Curve Diffie-Hellman (ECDH) on secp256k1.

    DISCLAIMER: This implementation is a mathematically rigorous secp256k1
    ECDH primitive, strictly utilizing a SHA-256 KDF on the X-coordinate to
    generate symmetric keys, intended for educational and architectural
    demonstration.
    """

    # secp256k1 Constants
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
            k: Integer to invert.
            mod: Modulus.

        Returns:
            The modular inverse of k modulo mod.

        Raises:
            ZeroDivisionError: If the modular inverse does not exist.
        """
        try:
            return pow(k, -1, mod)
        except ValueError:
            raise ZeroDivisionError("Modular inverse does not exist")

    @classmethod
    def _add_points(
        cls, p1: tuple[int, int] | None, p2: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        """
        Perform elliptic curve point addition over the prime field P.

        Args:
            p1: First point (x, y) or None for infinity.
            p2: Second point (x, y) or None for infinity.

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
            k: Scalar factor.
            point: Base point (x, y) or None.

        Returns:
            The resulting point (x, y) or None.
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
            A tuple (private_key, public_key_point).
        """
        d = secrets.randbelow(cls.N - 1) + 1
        q = cls._scalar_mult(d, cls.G)
        return d, q  # type: ignore

    def compute_shared_secret(
        self, private_key: int, peer_public_key: tuple[int, int]
    ) -> str:
        """
        Compute a shared secret using ECDH with KDF.

        Args:
            private_key: Local private key.
            peer_public_key: Remote public key point (x, y).

        Returns:
            SHA-256 hashed shared secret, Base64 encoded.

        Raises:
            ValueError: If peer_public_key is invalid or shared point is infinity.
        """
        x, y = peer_public_key

        # Validate point is on the curve
        if (y * y) % self.P != (pow(x, 3, self.P) + 7) % self.P:
            raise ValueError("Peer public key is not a valid point on secp256k1")

        shared_point = self._scalar_mult(private_key, peer_public_key)

        if shared_point is None:
            raise ValueError("Computed shared point is at infinity")

        x_coordinate = shared_point[0]
        x_bytes = x_coordinate.to_bytes(32, "big")

        shared_hash = hashlib.sha256(x_bytes).digest()
        return base64.b64encode(shared_hash).decode("utf-8")
