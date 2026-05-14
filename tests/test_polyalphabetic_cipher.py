import unittest
from backend.algorithms.polyalphabetic_cipher import PolyalphabeticCipher

class TestPolyalphabeticCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = PolyalphabeticCipher()

    def test_validate_key(self):
        # Valid
        self.cipher.validate_key("LEMON")
        # Empty
        with self.assertRaises(ValueError):
            self.cipher.validate_key("")
        # Non-alpha
        with self.assertRaises(ValueError):
            self.cipher.validate_key("LEMON123")

    def test_generate_key_stream(self):
        text = "ATTACK AT DAWN"
        key = "LEMON"
        # A T T A C K   A T   D A W N
        # L E M O N L   E M   O N L E
        # Note: Spaces are preserved in the stream for alignment
        expected = "LEMONL EM ONLE"
        stream = PolyalphabeticCipher._generate_key_stream(text, key)
        self.assertEqual(stream, expected)

    def test_encrypt_basic(self):
        plaintext = "ATTACK AT DAWN"
        key = "LEMON"
        # A+L=L, T+E=X, T+M=F, A+O=O, C+N=P, K+L=V
        # A+E=E, T+M=F
        # D+O=R, A+N=N, W+L=H, N+E=R
        # LXFOPV EF RNHR
        expected = "LXFOPV EF RNHR"
        result = self.cipher.encrypt(plaintext, key)
        self.assertEqual(result, expected)

    def test_encrypt_case_preservation(self):
        plaintext = "Attack at Dawn!"
        key = "lemon"
        expected = "Lxfopv ef Rnhr!"
        result = self.cipher.encrypt(plaintext, key)
        self.assertEqual(result, expected)

    def test_decrypt_basic(self):
        ciphertext = "LXFOPV EF RNHR"
        key = "LEMON"
        expected = "ATTACK AT DAWN"
        result = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(result, expected)

    def test_encrypt_decrypt_identity(self):
        plaintext = "The quick brown fox jumps over 13 lazy dogs."
        key = "KEYWORD"
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", "KEY"), "")
        self.assertEqual(self.cipher.decrypt("", "KEY"), "")

if __name__ == "__main__":
    unittest.main()
