import unittest
from backend.algorithms.seal_cipher import SEALCipher

class TestSEALCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = SEALCipher()
        self.key = "StandardSEALKey"
        self.position = 12345

    def test_validate_parameters(self):
        key_bytes, pos = SEALCipher.validate_parameters(self.key, self.position)
        self.assertEqual(len(key_bytes), 20)
        self.assertEqual(pos, self.position)
        
        with self.assertRaises(ValueError):
            SEALCipher.validate_parameters(self.key, -1)
        with self.assertRaises(ValueError):
            SEALCipher.validate_parameters(self.key, 0xFFFFFFFF + 1)

    def test_encrypt_decrypt_identity(self):
        plaintext = "Software-Optimized Encryption Algorithm (SEAL) 3.0"
        ciphertext = self.cipher.encrypt(plaintext, self.key, self.position)
        decrypted = self.cipher.decrypt(ciphertext, self.key, self.position)
        self.assertEqual(decrypted, plaintext)

    def test_different_positions(self):
        plaintext = "Same key, different positions"
        c1 = self.cipher.encrypt(plaintext, self.key, 0)
        c2 = self.cipher.encrypt(plaintext, self.key, 1)
        self.assertNotEqual(c1, c2)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.key, self.position), "")
        self.assertEqual(self.cipher.decrypt("", self.key, self.position), "")

    def test_invalid_base64(self):
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt("!!!NotBase64!!!", self.key, self.position)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid Base64 payload.")

if __name__ == "__main__":
    unittest.main()
