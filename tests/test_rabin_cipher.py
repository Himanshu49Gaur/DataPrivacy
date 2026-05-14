import unittest
from backend.algorithms.rabin_cipher import RabinCipher


class TestRabinCipher(unittest.TestCase):
    """Test suite for RabinCipher implementation."""

    @classmethod
    def setUpClass(cls):
        """Set up keypair once for all tests to save time."""
        cls.cipher = RabinCipher()
        # Using a smaller keysize for faster tests, though 1024 is default
        cls.pub_key, cls.priv_key = cls.cipher.generate_keypair(512)

    def test_encrypt_decrypt_cycle(self):
        """Tests a complete encryption/decryption cycle."""
        message = "Hello, Rabin Cryptosystem!"
        encrypted = self.cipher.encrypt(message, self.pub_key)
        decrypted = self.cipher.decrypt(encrypted, self.priv_key)

        self.assertEqual(message, decrypted)

    def test_shorter_message(self):
        """Tests encryption with a very short message."""
        message = "A"
        encrypted = self.cipher.encrypt(message, self.pub_key)
        decrypted = self.cipher.decrypt(encrypted, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_checksum_disambiguation(self):
        """Tests that root disambiguation correctly finds the right root."""
        message = "Verification test"
        encrypted = self.cipher.encrypt(message, self.pub_key)
        decrypted = self.cipher.decrypt(encrypted, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_invalid_ciphertext_raises_error(self):
        """Tests that invalid ciphertext causes a ValueError."""
        with self.assertRaises(ValueError):
            self.cipher.decrypt("aW52YWxpZA==", self.priv_key)

    def test_message_too_large(self):
        """Tests that messages exceeding block size raise ValueError."""
        # Create a message that will definitely exceed 512 bits after padding
        large_message = "X" * 100
        with self.assertRaises(ValueError):
            self.cipher.encrypt(large_message, self.pub_key)


if __name__ == "__main__":
    unittest.main()
