import unittest
from backend.algorithms.salsa20_cipher import Salsa20Cipher


class TestSalsa20Cipher(unittest.TestCase):
    """Test suite for Salsa20Cipher implementation."""

    def setUp(self):
        self.cipher = Salsa20Cipher()
        self.key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
        self.nonce = b"01234567"  # 8 bytes

    def test_encrypt_decrypt_cycle(self):
        """Tests a complete encryption/decryption cycle."""
        message = "This is a secret message for Salsa20 testing."
        encrypted = self.cipher.encrypt(message, self.key, self.nonce)
        decrypted = self.cipher.decrypt(encrypted, self.key, self.nonce)
        self.assertEqual(message, decrypted)

    def test_multi_block_message(self):
        """Tests encryption and decryption of a message longer than one block (64 bytes)."""
        message = "Salsa20 is a stream cipher developed by Daniel J. Bernstein. " * 5
        encrypted = self.cipher.encrypt(message, self.key, self.nonce)
        decrypted = self.cipher.decrypt(encrypted, self.key, self.nonce)
        self.assertEqual(message, decrypted)

    def test_different_nonce_different_ciphertext(self):
        """Tests that different nonces produce different results for the same message and key."""
        message = "Same Message"
        nonce2 = b"abcdefgh"
        enc1 = self.cipher.encrypt(message, self.key, self.nonce)
        enc2 = self.cipher.encrypt(message, self.key, nonce2)
        self.assertNotEqual(enc1, enc2)

    def test_invalid_key_length(self):
        """Tests that invalid key lengths raise ValueError."""
        with self.assertRaises(ValueError):
            self.cipher.encrypt("Test", b"short_key", self.nonce)

    def test_invalid_nonce_length(self):
        """Tests that invalid nonce lengths raise ValueError."""
        with self.assertRaises(ValueError):
            self.cipher.encrypt("Test", self.key, b"short_nonce")


if __name__ == "__main__":
    unittest.main()
