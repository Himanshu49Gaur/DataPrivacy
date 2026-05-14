import unittest
from backend.algorithms.aes_cipher import AESCipher


class TestAESCipher(unittest.TestCase):
    """Test suite for AESCipher implementation."""

    def setUp(self):
        self.cipher = AESCipher()
        self.key = "this_is_a_32_byte_key_for_aes256"  # Exactly 32 bytes

    def test_gcm_cycle(self):
        """Tests AES-GCM encryption and decryption."""
        message = "Secure message via GCM"
        encrypted = self.cipher.encrypt_gcm(message, self.key)
        decrypted = self.cipher.decrypt_gcm(encrypted, self.key)
        self.assertEqual(message, decrypted)

    def test_gcm_tamper_detection(self):
        """Tests that GCM detects ciphertext tampering."""
        message = "Tamper test"
        encrypted = self.cipher.encrypt_gcm(message, self.key)
        
        # Corrupt the ciphertext part (last byte)
        import base64
        data = bytearray(base64.b64decode(encrypted))
        data[-1] ^= 0x01
        tampered = base64.b64encode(data).decode("utf-8")
        
        with self.assertRaises(ValueError):
            self.cipher.decrypt_gcm(tampered, self.key)

    def test_cbc_cycle(self):
        """Tests AES-CBC encryption and decryption."""
        message = "Legacy message via CBC"
        encrypted = self.cipher.encrypt_cbc(message, self.key)
        decrypted = self.cipher.decrypt_cbc(encrypted, self.key)
        self.assertEqual(message, decrypted)

    def test_cbc_invalid_padding(self):
        """Tests that CBC raises error on invalid padding/key."""
        message = "Padding test"
        encrypted = self.cipher.encrypt_cbc(message, self.key)
        wrong_key = "wrong_key_must_be_32_bytes_long!"
        
        with self.assertRaises(ValueError):
            self.cipher.decrypt_cbc(encrypted, wrong_key)

    def test_invalid_key_length(self):
        """Tests that invalid key lengths are rejected."""
        with self.assertRaises(ValueError):
            self.cipher.validate_key("too_short")
        with self.assertRaises(ValueError):
            self.cipher.validate_key("A" * 33)


if __name__ == "__main__":
    unittest.main()
