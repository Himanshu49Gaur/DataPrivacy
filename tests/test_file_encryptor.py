import unittest
import os
from backend.algorithms.file_encryptor import FileEncryptor


class TestFileEncryptor(unittest.TestCase):
    """Test suite for FileEncryptor implementation."""

    def setUp(self):
        self.key = b"this_is_a_32_byte_key_for_aes256"
        self.test_file = "test_data.txt"
        self.enc_file = "test_data.enc"
        self.dec_file = "test_data.dec"
        
        with open(self.test_file, "w") as f:
            f.write("This is a test file for secure encryption. " * 1000)

    def tearDown(self):
        for f in [self.test_file, self.enc_file, self.dec_file]:
            if os.path.exists(f):
                os.remove(f)

    def test_file_encrypt_decrypt_cycle(self):
        """Tests a complete file encryption and decryption cycle."""
        FileEncryptor.encrypt_file(self.test_file, self.enc_file, self.key)
        self.assertTrue(os.path.exists(self.enc_file))
        
        FileEncryptor.decrypt_file(self.enc_file, self.dec_file, self.key)
        self.assertTrue(os.path.exists(self.dec_file))
        
        with open(self.test_file, "r") as f1, open(self.dec_file, "r") as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_tamper_detection(self):
        """Tests that tampering with the encrypted file causes decryption failure."""
        FileEncryptor.encrypt_file(self.test_file, self.enc_file, self.key)
        
        # Tamper with the encrypted data (after nonce and tag)
        with open(self.enc_file, "r+b") as f:
            f.seek(33) # After header
            byte = f.read(1)
            f.seek(33)
            f.write(bytes([byte[0] ^ 0x01]))
            
        with self.assertRaises(ValueError):
            FileEncryptor.decrypt_file(self.enc_file, self.dec_file, self.key)

    def test_invalid_key_length(self):
        """Tests that invalid key lengths are rejected."""
        with self.assertRaises(ValueError):
            FileEncryptor.encrypt_file(self.test_file, self.enc_file, b"short")


if __name__ == "__main__":
    unittest.main()
