import hashlib
import base64
import secrets


class HMACAuth:
    """
    Highly optimized implementation of HMAC-SHA256 (RFC 2104).

    This module provides message authentication and data integrity verification
    using the HMAC algorithm with SHA-256. It implements the ARX-based XOR
    pad transformation to ensure architectural depth and security.
    """

    BLOCK_SIZE = 64  # SHA-256 block size
    IPAD = 0x36
    OPAD = 0x5C

    @classmethod
    def generate_key(cls, bits: int = 256) -> str:
        """
        Generate a cryptographically secure random key for HMAC.

        Args:
            bits: The number of bits for the key (default 256).

        Returns:
            The key as a Base64 encoded string.
        """
        key_bytes = secrets.token_bytes(bits // 8)
        return base64.b64encode(key_bytes).decode("utf-8")

    @classmethod
    def compute_hmac(cls, message: str, key: str) -> str:
        """
        Compute the HMAC-SHA256 tag for a given message and key.

        Args:
            message: The UTF-8 message to authenticate.
            key: The Base64 encoded authentication key.

        Returns:
            The Base64 encoded HMAC tag.
        """
        # Decode key and handle length constraints
        try:
            k = base64.b64decode(key)
        except Exception:
            k = key.encode("utf-8")  # Fallback to UTF-8 if not Base64

        if len(k) > cls.BLOCK_SIZE:
            k = hashlib.sha256(k).digest()
        if len(k) < cls.BLOCK_SIZE:
            k = k + b"\x00" * (cls.BLOCK_SIZE - len(k))

        # Compute inner and outer pads
        k_ipad = bytes([b ^ cls.IPAD for b in k])
        k_opad = bytes([b ^ cls.OPAD for b in k])

        # Compute HMAC: H(K_opad || H(K_ipad || m))
        inner_hash = hashlib.sha256(k_ipad + message.encode("utf-8")).digest()
        outer_hash = hashlib.sha256(k_opad + inner_hash).digest()

        return base64.b64encode(outer_hash).decode("utf-8")

    @classmethod
    def verify_hmac(cls, message: str, key: str, tag: str) -> bool:
        """
        Verify an HMAC tag using constant-time comparison.

        Args:
            message: The original UTF-8 message.
            key: The authentication key.
            tag: The Base64 encoded HMAC tag to verify.

        Returns:
            True if the tag is valid, False otherwise.
        """
        try:
            expected_tag = cls.compute_hmac(message, key)
            return secrets.compare_digest(expected_tag, tag)
        except Exception:
            return False
