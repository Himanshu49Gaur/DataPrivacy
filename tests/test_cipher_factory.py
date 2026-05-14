import unittest
from backend.algorithms.factory import CipherFactory
from backend.algorithms.aes_cipher import AESCipher
from backend.algorithms.chacha20_cipher import ChaCha20Cipher


class TestCipherFactory(unittest.TestCase):
    """Test suite for CipherFactory implementation."""

    def test_create_valid_cipher(self):
        """Tests that valid ciphers are instantiated correctly."""
        aes = CipherFactory.create("AES")
        self.assertIsInstance(aes, AESCipher)
        
        chacha = CipherFactory.create("ChaCha20")
        self.assertIsInstance(chacha, ChaCha20Cipher)

    def test_create_invalid_cipher_raises_error(self):
        """Tests that invalid cipher names raise ValueError."""
        with self.assertRaises(ValueError):
            CipherFactory.create("InvalidCipher")

    def test_list_algorithms(self):
        """Tests that list_algorithms returns a non-empty list of strings."""
        algorithms = CipherFactory.list_algorithms()
        self.assertIsInstance(algorithms, list)
        self.assertGreater(len(algorithms), 0)
        self.assertIn("AES", algorithms)
        self.assertIn("RSA", algorithms)
        self.assertIn("ChaCha20", algorithms)

    def test_all_registered_ciphers_can_be_created(self):
        """Tests that every algorithm in the registry can be instantiated."""
        for name in CipherFactory.list_algorithms():
            cipher = CipherFactory.create(name)
            self.assertIsNotNone(cipher)


if __name__ == "__main__":
    unittest.main()
