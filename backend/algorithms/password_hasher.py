import base64
import secrets
from typing import Tuple
from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Hash import SHA256


class PasswordHasher:
    """
    Highly optimized implementation of password hashing using Scrypt and PBKDF2.

    This module provides secure password storage mechanisms utilizing modern
    Key Derivation Functions (KDFs) to protect against brute-force and
    rainbow table attacks.
    """

    SALT_SIZE = 16
    KEY_LEN = 32

    @classmethod
    def hash_password_scrypt(cls, password: str) -> str:
        """
        Hash a password using the Scrypt algorithm.

        Args:
            password: The plaintext password.

        Returns:
            The Base64 encoded salt and derived key.
        """
        salt = secrets.token_bytes(cls.SALT_SIZE)
        # N=16384 (CPU/memory cost), r=8 (block size), p=1 (parallelization)
        key = scrypt(password.encode("utf-8"), salt, cls.KEY_LEN, N=16384, r=8, p=1)
        
        payload = salt + key
        return base64.b64encode(payload).decode("utf-8")

    @classmethod
    def verify_password_scrypt(cls, password: str, hashed: str) -> bool:
        """
        Verify a password against a Scrypt hash.

        Args:
            password: The plaintext password to verify.
            hashed: The Base64 encoded salt and key.

        Returns:
            True if the password matches, False otherwise.
        """
        try:
            payload = base64.b64decode(hashed)
            salt = payload[: cls.SALT_SIZE]
            expected_key = payload[cls.SALT_SIZE :]
            
            actual_key = scrypt(
                password.encode("utf-8"), salt, cls.KEY_LEN, N=16384, r=8, p=1
            )
            return secrets.compare_digest(actual_key, expected_key)
        except Exception:
            return False

    @classmethod
    def hash_password_pbkdf2(cls, password: str) -> str:
        """
        Hash a password using PBKDF2-HMAC-SHA256.

        Args:
            password: The plaintext password.

        Returns:
            The Base64 encoded salt and derived key.
        """
        salt = secrets.token_bytes(cls.SALT_SIZE)
        key = PBKDF2(
            password.encode("utf-8"),
            salt,
            cls.KEY_LEN,
            count=100000,
            hmac_hash_module=SHA256,
        )
        
        payload = salt + key
        return base64.b64encode(payload).decode("utf-8")

    @classmethod
    def verify_password_pbkdf2(cls, password: str, hashed: str) -> bool:
        """
        Verify a password against a PBKDF2 hash.

        Args:
            password: The plaintext password to verify.
            hashed: The Base64 encoded salt and key.

        Returns:
            True if the password matches, False otherwise.
        """
        try:
            payload = base64.b64decode(hashed)
            salt = payload[: cls.SALT_SIZE]
            expected_key = payload[cls.SALT_SIZE :]
            
            actual_key = PBKDF2(
                password.encode("utf-8"),
                salt,
                cls.KEY_LEN,
                count=100000,
                hmac_hash_module=SHA256,
            )
            return secrets.compare_digest(actual_key, expected_key)
        except Exception:
            return False
