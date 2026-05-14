from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512


class SHA3Hasher:
    """
    Highly optimized implementation of SHA-3 (Keccak) hashing.

    This module provides hashing capabilities for all standard SHA-3
    output lengths (224, 256, 384, and 512 bits) as specified by NIST.
    """

    @classmethod
    def _to_bytes(cls, data: str | bytes) -> bytes:
        """Convert input to bytes if it is a string."""
        if isinstance(data, str):
            return data.encode("utf-8")
        return data

    @classmethod
    def hash_224(cls, data: str | bytes) -> str:
        """
        Compute the SHA3-224 hash.

        Args:
            data: The input string or bytes.

        Returns:
            The hexadecimal digest string.
        """
        h = SHA3_224.new(cls._to_bytes(data))
        return h.hexdigest()

    @classmethod
    def hash_256(cls, data: str | bytes) -> str:
        """
        Compute the SHA3-256 hash.

        Args:
            data: The input string or bytes.

        Returns:
            The hexadecimal digest string.
        """
        h = SHA3_256.new(cls._to_bytes(data))
        return h.hexdigest()

    @classmethod
    def hash_384(cls, data: str | bytes) -> str:
        """
        Compute the SHA3-384 hash.

        Args:
            data: The input string or bytes.

        Returns:
            The hexadecimal digest string.
        """
        h = SHA3_384.new(cls._to_bytes(data))
        return h.hexdigest()

    @classmethod
    def hash_512(cls, data: str | bytes) -> str:
        """
        Compute the SHA3-512 hash.

        Args:
            data: The input string or bytes.

        Returns:
            The hexadecimal digest string.
        """
        h = SHA3_512.new(cls._to_bytes(data))
        return h.hexdigest()
