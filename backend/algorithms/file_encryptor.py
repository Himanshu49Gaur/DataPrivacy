import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class FileEncryptor:
    """
    Highly optimized implementation of secure file encryption using AES-256-GCM.

    This module provides authenticated encryption for files on disk, ensuring
    both confidentiality and integrity through a buffered processing strategy.
    """

    BUFFER_SIZE = 64 * 1024  # 64KB buffer
    NONCE_SIZE = 16
    TAG_SIZE = 16

    @classmethod
    def encrypt_file(cls, input_path: str, output_path: str, key: bytes) -> None:
        """
        Encrypt a file using AES-256-GCM.

        Output format: [16 bytes Nonce] + [16 bytes Tag] + [Ciphertext]

        Args:
            input_path: Path to the source file.
            output_path: Path to the destination encrypted file.
            key: 32-byte AES key.

        Raises:
            ValueError: If the key length is invalid.
            FileNotFoundError: If the input file does not exist.
        """
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")

        nonce = get_random_bytes(cls.NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Reserve space for nonce and tag (nonce written now, tag later)
            f_out.write(nonce)
            f_out.write(b"\x00" * cls.TAG_SIZE)

            while True:
                chunk = f_in.read(cls.BUFFER_SIZE)
                if len(chunk) == 0:
                    break
                f_out.write(cipher.encrypt(chunk))

            tag = cipher.digest()
            # Seek back to write the authentication tag
            f_out.seek(cls.NONCE_SIZE)
            f_out.write(tag)

    @classmethod
    def decrypt_file(cls, input_path: str, output_path: str, key: bytes) -> None:
        """
        Decrypt a file using AES-256-GCM.

        Args:
            input_path: Path to the encrypted source file.
            output_path: Path to the destination decrypted file.
            key: 32-byte AES key.

        Raises:
            ValueError: If authentication fails or key is invalid.
            FileNotFoundError: If the input file does not exist.
        """
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")

        with open(input_path, "rb") as f_in:
            nonce = f_in.read(cls.NONCE_SIZE)
            tag = f_in.read(cls.TAG_SIZE)
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            with open(output_path, "wb") as f_out:
                while True:
                    chunk = f_in.read(cls.BUFFER_SIZE)
                    if len(chunk) == 0:
                        break
                    f_out.write(cipher.decrypt(chunk))
                
                try:
                    cipher.verify(tag)
                except ValueError:
                    # Authentication failed - delete the partial file for safety
                    f_out.close()
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise ValueError("MAC check failed: File corrupted or invalid key")
