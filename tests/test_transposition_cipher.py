import unittest
from backend.algorithms.transposition_cipher import TranspositionCipher

class TestTranspositionCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = TranspositionCipher()
        self.key = "ZEBRA" # Order: 4, 1, 0, 3, 2 (Z:4, E:1, B:0, R:3, A:2) -> A:2, B:0, E:1, R:3, Z:4

    def test_validate_key(self):
        # Valid
        self.cipher.validate_key("ZEBRA")
        # Empty
        with self.assertRaises(ValueError):
            self.cipher.validate_key("")
        # Non-alpha
        with self.assertRaises(ValueError):
            self.cipher.validate_key("KEY123")
        # Duplicates
        with self.assertRaises(ValueError):
            self.cipher.validate_key("APPLE")

    def test_get_column_order(self):
        # ZEBRA -> A:0, B:1, E:2, R:3, Z:4 alphabetically.
        # Original indices: Z:0, E:1, B:2, R:3, A:4
        # A(4), B(2), E(1), R(3), Z(0)
        order = TranspositionCipher._get_column_order("ZEBRA")
        self.assertEqual(order, [4, 2, 1, 3, 0])

    def test_encrypt_basic(self):
        # Plaintext: "PIRATE" (len 6)
        # Key: "ZEBRA" (len 5)
        # Grid (irregular):
        # P I R A T
        # E
        # Col 0 (Z): P, E
        # Col 1 (E): I
        # Col 2 (B): R
        # Col 3 (R): A
        # Col 4 (A): T
        # Order (A, B, E, R, Z): 4, 2, 1, 3, 0
        # Expected: T + R + I + A + PE = TRIA PE
        # Correct order calculation for ZEBRA:
        # 0:Z, 1:E, 2:B, 3:R, 4:A
        # Sorted: A(4), B(2), E(1), R(3), Z(0)
        # Ciphertext: T R I A PE
        plaintext = "PIRATE"
        expected = "TRIAPE"
        result = self.cipher.encrypt(plaintext, "ZEBRA")
        self.assertEqual(result, expected)

    def test_decrypt_basic(self):
        ciphertext = "TRIAPE"
        expected = "PIRATE"
        result = self.cipher.decrypt(ciphertext, "ZEBRA")
        self.assertEqual(result, expected)

    def test_encrypt_decrypt_identity(self):
        plaintext = "Common sense is not so common."
        key = "SECRET" # Sorted: C(2), E(1), E(3), R(4), S(0), T(5) -> Wait, unique chars only.
        key = "BACKLY" # Sorted: A(1), B(0), C(2), K(3), L(4), Y(5)
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", "KEY"), "")
        self.assertEqual(self.cipher.decrypt("", "KEY"), "")

if __name__ == "__main__":
    unittest.main()
