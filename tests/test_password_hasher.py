import unittest
from backend.algorithms.password_hasher import PasswordHasher


class TestPasswordHasher(unittest.TestCase):
    """Test suite for PasswordHasher implementation."""

    def test_scrypt_cycle(self):
        """Tests complete Scrypt hashing and verification cycle."""
        password = "MySecurePassword123!"
        hashed = PasswordHasher.hash_password_scrypt(password)
        
        self.assertTrue(PasswordHasher.verify_password_scrypt(password, hashed))
        self.assertFalse(PasswordHasher.verify_password_scrypt("WrongPassword", hashed))

    def test_pbkdf2_cycle(self):
        """Tests complete PBKDF2 hashing and verification cycle."""
        password = "AnotherSecurePassword!"
        hashed = PasswordHasher.hash_password_pbkdf2(password)
        
        self.assertTrue(PasswordHasher.verify_password_pbkdf2(password, hashed))
        self.assertFalse(PasswordHasher.verify_password_pbkdf2("WrongPassword", hashed))

    def test_salting_uniqueness(self):
        """Tests that same passwords produce different hashes due to salting."""
        password = "SamePassword"
        hash1 = PasswordHasher.hash_password_scrypt(password)
        hash2 = PasswordHasher.hash_password_scrypt(password)
        
        self.assertNotEqual(hash1, hash2)

    def test_invalid_hash_handling(self):
        """Tests that malformed hashes do not crash the verifier."""
        self.assertFalse(PasswordHasher.verify_password_scrypt("password", "invalid_base64"))
        self.assertFalse(PasswordHasher.verify_password_pbkdf2("password", "short"))


if __name__ == "__main__":
    unittest.main()
