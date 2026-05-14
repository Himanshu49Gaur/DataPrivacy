import unittest
from backend.algorithms.nlfsr_cipher import NLFSRCipher

class TestNLFSRCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = NLFSRCipher()
        self.seed = "1101"
        self.anf_terms = [(0, 1), (2,)] # (bit[0] AND bit[1]) XOR bit[2]

    def test_validate_parameters_valid(self):
        seed_list, anf_terms = NLFSRCipher.validate_parameters(self.seed, self.anf_terms)
        self.assertEqual(seed_list, [1, 1, 0, 1])
        self.assertEqual(anf_terms, self.anf_terms)

    def test_validate_parameters_invalid(self):
        # Empty seed
        with self.assertRaises(ValueError):
            NLFSRCipher.validate_parameters("", [(0,)])
        # Non-binary
        with self.assertRaises(ValueError):
            NLFSRCipher.validate_parameters("1021", [(0,)])
        # Out of range terms
        with self.assertRaises(ValueError):
            NLFSRCipher.validate_parameters("1101", [(4,)])

    def test_encrypt_decrypt_identity(self):
        plaintext = "Non-linear feedback"
        ciphertext = self.cipher.encrypt(plaintext, self.seed, self.anf_terms)
        decrypted = self.cipher.decrypt(ciphertext, self.seed, self.anf_terms)
        self.assertEqual(decrypted, plaintext)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.seed, self.anf_terms), "")
        self.assertEqual(self.cipher.decrypt("", self.seed, self.anf_terms), "")

    def test_invalid_base64(self):
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt("!!!", self.seed, self.anf_terms)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid Base64 payload.")

if __name__ == "__main__":
    unittest.main()
