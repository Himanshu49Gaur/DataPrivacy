import unittest
from backend.algorithms.monoalphabetic_cipher import MonoalphabeticCipher

class TestMonoalphabeticCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = MonoalphabeticCipher()
        self.valid_key = "QWERTYUIOPASDFGHJKLZXCVBNM"

    def test_generate_key(self):
        key = MonoalphabeticCipher.generate_key()
        self.assertEqual(len(key), 26)
        self.assertTrue(key.isupper())
        self.assertEqual(len(set(key)), 26)
        self.assertTrue(key.isalpha())

    def test_validate_key_valid(self):
        try:
            MonoalphabeticCipher.validate_key(self.valid_key)
        except ValueError:
            self.fail("validate_key() raised ValueError unexpectedly!")

    def test_validate_key_invalid_length(self):
        with self.assertRaises(ValueError) as cm:
            MonoalphabeticCipher.validate_key("ABC")
        self.assertEqual(str(cm.exception), "Key must be exactly 26 characters long.")

    def test_validate_key_non_alpha(self):
        with self.assertRaises(ValueError) as cm:
            MonoalphabeticCipher.validate_key("QWERTYUIOPASDFGHJKLZXCVBN1")
        self.assertEqual(str(cm.exception), "Key must contain only alphabetic characters.")

    def test_validate_key_duplicates(self):
        with self.assertRaises(ValueError) as cm:
            MonoalphabeticCipher.validate_key("AAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertEqual(str(cm.exception), "Key must contain 26 unique characters.")

    def test_encrypt_basic(self):
        plaintext = "Hello World"
        # Key: QWERTYUIOPASDFGHJKLZXCVBNM
        # A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
        # Q W E R T Y U I O P A S D F G H J K L Z X C V B N M
        # H(8)->I, e(5)->t, l(12)->s, o(15)->g
        # W(23)->V, o(15)->g, r(18)->k, l(12)->s, d(4)->r
        # Expected: Itssg Vgksr
        expected = "Itssg Vgksr"
        result = self.cipher.encrypt(plaintext, self.valid_key)
        self.assertEqual(result, expected)

    def test_decrypt_basic(self):
        ciphertext = "Itssg Vgksr"
        expected = "Hello World"
        result = self.cipher.decrypt(ciphertext, self.valid_key)
        self.assertEqual(result, expected)

    def test_encrypt_decrypt_identity(self):
        plaintext = "The quick brown fox jumps over the lazy dog! 123"
        key = MonoalphabeticCipher.generate_key()
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.valid_key), "")
        self.assertEqual(self.cipher.decrypt("", self.valid_key), "")

if __name__ == "__main__":
    unittest.main()
