import unittest
from backend.algorithms.lfsr_cipher import LFSRCipher

class TestLFSRCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = LFSRCipher()
        self.seed = "1011"
        self.taps = [0, 3]

    def test_validate_parameters_valid(self):
        seed_list, taps = LFSRCipher.validate_parameters(self.seed, self.taps)
        self.assertEqual(seed_list, [1, 0, 1, 1])
        self.assertEqual(taps, [0, 3])

    def test_validate_parameters_invalid(self):
        # Empty seed
        with self.assertRaises(ValueError):
            LFSRCipher.validate_parameters("", [0])
        # Non-binary
        with self.assertRaises(ValueError):
            LFSRCipher.validate_parameters("1021", [0])
        # All zeros
        with self.assertRaises(ValueError):
            LFSRCipher.validate_parameters("0000", [0])
        # Out of range taps
        with self.assertRaises(ValueError):
            LFSRCipher.validate_parameters("1011", [4])

    def test_encrypt_decrypt_identity(self):
        plaintext = "Hello World"
        ciphertext = self.cipher.encrypt(plaintext, self.seed, self.taps)
        decrypted = self.cipher.decrypt(ciphertext, self.seed, self.taps)
        self.assertEqual(decrypted, plaintext)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.seed, self.taps), "")
        self.assertEqual(self.cipher.decrypt("", self.seed, self.taps), "")

    def test_invalid_base64(self):
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt("!!!", self.seed, self.taps)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid Base64 payload.")

if __name__ == "__main__":
    unittest.main()
