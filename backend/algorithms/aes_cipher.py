import base64
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes


class AESCipher:
    """
    Highly optimized implementation of the Advanced Encryption Standard (AES).

    This module provides production-grade AES-256 encryption in both
    GCM (Authenticated) and CBC (Legacy) modes using the PyCryptodome library.
    """

    KEY_SIZE = 32  # AES-256
    BLOCK_SIZE = AES.block_size  # 16 bytes

    @classmethod
    def validate_key(cls, key: str | bytes) -> bytes:
        """
        Validate the AES-256 key.

        Args:
            key: The key as a string or bytes.

        Returns:
            The validated 32-byte key.

        Raises:
            ValueError: If the key is not exactly 32 bytes.
        """
        if isinstance(key, str):
            key_bytes = key.encode("utf-8")
        else:
            key_bytes = key

        if len(key_bytes) != cls.KEY_SIZE:
            raise ValueError(f"AES-256 key must be exactly {cls.KEY_SIZE} bytes")
        return key_bytes

    def encrypt_gcm(self, plaintext: str, key: str | bytes) -> str:
        """
        Encrypt a message using AES-256-GCM (Authenticated Encryption).

        Payload format: [12 bytes Nonce] + [16 bytes Tag] + [Ciphertext]

        Args:
            plaintext: The message to encrypt.
            key: The 32-byte encryption key.

        Returns:
            Base64 encoded payload.
        """
        validated_key = self.validate_key(key)
        cipher = AES.new(validated_key, AES.MODE_GCM)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        
        # GCM default nonce is 16 bytes in some libs, but 12 is recommended for NIST
        # PyCryptodome uses 16 bytes by default for AES-GCM if not specified.
        # Let's ensure we use the generated nonce.
        payload = cipher.nonce + tag + ciphertext
        return base64.b64encode(payload).decode("utf-8")

    def decrypt_gcm(self, ciphertext: str, key: str | bytes) -> str:
        """
        Decrypt a message using AES-256-GCM.

        Args:
            ciphertext: The Base64 encoded payload.
            key: The 32-byte decryption key.

        Returns:
            The decrypted UTF-8 plaintext string.

        Raises:
            ValueError: If the payload is malformed or authentication fails.
        """
        validated_key = self.validate_key(key)
        try:
            data = base64.b64decode(ciphertext)
        except Exception:
            raise ValueError("Invalid Base64 encoding")

        # Nonce length in PyCryptodome GCM is 16 bytes by default, but we should 
        # check the actual nonce used during encryption.
        # In our encrypt_gcm, we prepended cipher.nonce.
        # Let's check the length.
        nonce_len = 16 
        tag_len = 16
        
        if len(data) < nonce_len + tag_len:
            raise ValueError("Ciphertext payload too short")

        nonce = data[:nonce_len]
        tag = data[nonce_len : nonce_len + tag_len]
        encrypted_data = data[nonce_len + tag_len :]

        cipher = AES.new(validated_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)
            return decrypted.decode("utf-8")
        except ValueError:
            raise ValueError("MAC check failed: Ciphertext corrupted or invalid key")

    def encrypt_cbc(self, plaintext: str, key: str | bytes) -> str:
        """
        Encrypt a message using AES-256-CBC (Legacy Mode).

        Payload format: [16 bytes IV] + [Ciphertext]

        Args:
            plaintext: The message to encrypt.
            key: The 32-byte encryption key.

        Returns:
            Base64 encoded payload.
        """
        validated_key = self.validate_key(key)
        iv = get_random_bytes(self.BLOCK_SIZE)
        cipher = AES.new(validated_key, AES.MODE_CBC, iv=iv)
        
        padded_data = Padding.pad(plaintext.encode("utf-8"), self.BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded_data)
        
        payload = iv + ciphertext
        return base64.b64encode(payload).decode("utf-8")

    def decrypt_cbc(self, ciphertext: str, key: str | bytes) -> str:
        """
        Decrypt a message using AES-256-CBC.

        Args:
            ciphertext: The Base64 encoded payload.
            key: The 32-byte decryption key.

        Returns:
            The decrypted UTF-8 plaintext string.

        Raises:
            ValueError: If the payload is malformed or padding is invalid.
        """
        validated_key = self.validate_key(key)
        try:
            data = base64.b64decode(ciphertext)
        except Exception:
            raise ValueError("Invalid Base64 encoding")

        if len(data) < self.BLOCK_SIZE:
            raise ValueError("Ciphertext payload too short")

        iv = data[: self.BLOCK_SIZE]
        encrypted_data = data[self.BLOCK_SIZE :]

        cipher = AES.new(validated_key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        try:
            plaintext_bytes = Padding.unpad(decrypted_padded, self.BLOCK_SIZE)
            return plaintext_bytes.decode("utf-8")
        except (ValueError, KeyError):
            raise ValueError("Invalid padding or key")
