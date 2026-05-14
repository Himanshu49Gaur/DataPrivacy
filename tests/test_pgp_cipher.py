import unittest
from backend.algorithms.pgp_cipher import PGPCipher


class TestPGPCipher(unittest.TestCase):
    """Test suite for PGPCipher implementation."""

    def setUp(self):
        """Set up keys for testing."""
        self.priv_key, self.pub_key = PGPCipher.generate_keypair(2048)

    def test_key_generation(self):
        """Tests that keys are generated and exported correctly."""
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", self.priv_key)
        self.assertIn("-----BEGIN PUBLIC KEY-----", self.pub_key)

    def test_encrypt_decrypt_cycle(self):
        """Tests a complete encryption/decryption cycle."""
        message = "This is a secret message for PGP testing."
        encrypted = PGPCipher.encrypt_message(message, self.pub_key)

        self.assertIn("-----BEGIN PGP MESSAGE-----", encrypted)
        self.assertIn("-----END PGP MESSAGE-----", encrypted)

        decrypted = PGPCipher.decrypt_message(encrypted, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_large_message(self):
        """Tests encryption and decryption of a larger payload."""
        message = "A" * 10000  # 10KB message
        encrypted = PGPCipher.encrypt_message(message, self.pub_key)
        decrypted = PGPCipher.decrypt_message(encrypted, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_invalid_key_raises_error(self):
        """Tests that decrypting with the wrong key fails."""
        message = "Top Secret"
        encrypted = PGPCipher.encrypt_message(message, self.pub_key)

        # Generate a different keypair
        other_priv, _ = PGPCipher.generate_keypair(2048)

        with self.assertRaises(ValueError):
            PGPCipher.decrypt_message(encrypted, other_priv)


if __name__ == "__main__":
    unittest.main()
