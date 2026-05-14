import base64
from Crypto.Cipher import Blowfish


class BlowfishCipher:
    """
    Highly optimized implementation of the Blowfish Block Cipher.

    DISCLAIMER: This implementation utilizes the PyCryptodome library and is
    implemented in Electronic Codebook (ECB) mode as an advanced cryptographic
    primitive for educational and architectural demonstration.
    """

    BLOCK_SIZE = Blowfish.block_size  # 8 bytes

    @classmethod
    def validate_key(cls, key: str) -> bytes:
        """
        Validate the Blowfish key length.

        Args:
            key: The UTF-8 string key.

        Returns:
            The validated key as bytes.

        Raises:
            ValueError: If the key length is outside the 4-56 byte range.
        """
        key_bytes = key.encode("utf-8")
        if not (4 <= len(key_bytes) <= 56):
            raise ValueError("Blowfish key must be between 4 and 56 bytes long")
        return key_bytes

    @classmethod
    def _pad(cls, data: bytes) -> bytes:
        """
        Apply PKCS#7 padding for the 8-byte block size.

        Args:
            data: The byte array to pad.

        Returns:
            The padded byte array.
        """
        padding_len = cls.BLOCK_SIZE - (len(data) % cls.BLOCK_SIZE)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @classmethod
    def _unpad(cls, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding.

        Args:
            data: The padded byte array.

        Returns:
            The unpadded byte array.

        Raises:
            ValueError: If the padding is invalid.
        """
        if not data:
            raise ValueError("Empty data cannot be unpadded")

        padding_len = data[-1]
        if padding_len < 1 or padding_len > cls.BLOCK_SIZE:
            raise ValueError("Invalid padding length")

        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid PKCS#7 padding")

        return data[:-padding_len]

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypt a message using Blowfish in ECB mode.

        Args:
            plaintext: The message to encrypt.
            key: The encryption key.

        Returns:
            The Base64 encoded ciphertext.
        """
        validated_key = self.validate_key(key)
        cipher = Blowfish.new(validated_key, Blowfish.MODE_ECB)

        padded_data = self._pad(plaintext.encode("utf-8"))
        ciphertext_bytes = cipher.encrypt(padded_data)

        return base64.b64encode(ciphertext_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypt a message using Blowfish in ECB mode.

        Args:
            ciphertext: The Base64 encoded ciphertext.
            key: The decryption key.

        Returns:
            The decrypted UTF-8 plaintext string.
        """
        validated_key = self.validate_key(key)
        cipher = Blowfish.new(validated_key, Blowfish.MODE_ECB)

        try:
            ciphertext_bytes = base64.b64decode(ciphertext)
        except Exception:
            raise ValueError("Invalid Base64 encoding")

        if len(ciphertext_bytes) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of the block size")

        decrypted_padded = cipher.decrypt(ciphertext_bytes)
        unpadded_data = self._unpad(decrypted_padded)

        return unpadded_data.decode("utf-8", errors="replace")
