import unittest
from backend.algorithms.rc4_cipher import RC4Cipher

class TestRC4Cipher(unittest.TestCase):
    def setUp(self):
        self.cipher = RC4Cipher()

    def test_validate_key(self):
        self.assertEqual(self.cipher.validate_key("Key"), b"Key")
        with self.assertRaises(ValueError):
            self.cipher.validate_key("")

    def test_encrypt_decrypt_identity(self):
        plaintext = "Hello World"
        key = "SecretKey"
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_vector(self):
        # Known vector for RC4: Key "Key", Plaintext "Plaintext"
        # Hex result should be BBF316E8D940AF0AD3
        # hex(187 243 22 232 217 64 175 10 211)
        key = "Key"
        plaintext = "Plaintext"
        # Expected result in Base64: u/MW6NlArwrT
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "u/MW6NlArwrT")

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", "Key"), "")
        self.assertEqual(self.cipher.decrypt("", "Key"), "")

    def test_invalid_base64(self):
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt("not base64!", "Key")
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid Base64 payload.")

if __name__ == "__main__":
    unittest.main()
