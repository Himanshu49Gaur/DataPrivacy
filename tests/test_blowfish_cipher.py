import unittest
from backend.algorithms.blowfish_cipher import BlowfishCipher


class TestBlowfishCipher(unittest.TestCase):
    """Test suite for BlowfishCipher implementation."""

    def setUp(self):
        self.cipher = BlowfishCipher()
        self.key = "secret_key_123"

    def test_encrypt_decrypt_cycle(self):
        """Tests a complete encryption/decryption cycle."""
        message = "This is a secret message for Blowfish testing."
        encrypted = self.cipher.encrypt(message, self.key)
        decrypted = self.cipher.decrypt(encrypted, self.key)
        self.assertEqual(message, decrypted)

    def test_invalid_key_length(self):
        """Tests that invalid key lengths raise ValueError."""
        with self.assertRaises(ValueError):
            self.cipher.validate_key("123")  # Too short (3 bytes)
        with self.assertRaises(ValueError):
            self.cipher.validate_key("A" * 57)  # Too long (57 bytes)

    def test_padding(self):
        """Tests PKCS#7 padding and unpadding logic."""
        data = b"Hello"
        padded = self.cipher._pad(data)
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded[-1], 3)
        self.assertEqual(self.cipher._unpad(padded), data)

    def test_invalid_padding_raises_error(self):
        """Tests that corrupted padding raises ValueError."""
        data = b"Padded!!" + b"\x07\x07\x07\x07\x07\x07\x06"  # Invalid last byte
        with self.assertRaises(ValueError):
            self.cipher._unpad(data)

    def test_different_keys_different_ciphertexts(self):
        """Tests that different keys produce different results."""
        message = "Same Message"
        enc1 = self.cipher.encrypt(message, "key_one_123")
        enc2 = self.cipher.encrypt(message, "key_two_123")
        self.assertNotEqual(enc1, enc2)


if __name__ == "__main__":
    unittest.main()
