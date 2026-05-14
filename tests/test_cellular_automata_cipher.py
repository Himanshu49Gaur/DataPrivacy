import unittest
from backend.algorithms.cellular_automata_cipher import CellularAutomataCipher

class TestCellularAutomataCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = CellularAutomataCipher()
        self.key = "SecretKey"

    def test_validate_parameters_valid(self):
        state, rule_map = CellularAutomataCipher.validate_parameters(self.key, 30)
        self.assertEqual(len(state), len(self.key) * 8)
        # Verify rule 30 mapping for some neighborhoods
        # 00011110
        # 111(7): 0, 110(6): 0, 101(5): 0, 100(4): 1, 011(3): 1, 010(2): 1, 001(1): 1, 000(0): 0
        self.assertEqual(rule_map[(1, 0, 0)], 1)
        self.assertEqual(rule_map[(0, 0, 0)], 0)
        self.assertEqual(rule_map[(1, 1, 1)], 0)

    def test_validate_parameters_invalid(self):
        with self.assertRaises(ValueError):
            CellularAutomataCipher.validate_parameters("", 30)
        with self.assertRaises(ValueError):
            CellularAutomataCipher.validate_parameters("key", 256)

    def test_encrypt_decrypt_identity(self):
        plaintext = "Hello World"
        ciphertext = self.cipher.encrypt(plaintext, self.key, 30)
        decrypted = self.cipher.decrypt(ciphertext, self.key, 30)
        self.assertEqual(decrypted, plaintext)

    def test_all_zeros_seed(self):
        # A key consisting of null bytes would result in all zeros
        key = "\x00\x00"
        state, _ = CellularAutomataCipher.validate_parameters(key, 30)
        self.assertTrue(sum(state) > 0) # Center bit should have been flipped

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.key), "")
        self.assertEqual(self.cipher.decrypt("", self.key), "")

if __name__ == "__main__":
    unittest.main()
