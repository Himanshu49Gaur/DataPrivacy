import unittest
from backend.algorithms.rsa_cipher import RSACipher


class TestRSACipher(unittest.TestCase):
    """Test suite for the RSACipher implementation."""

    def test_keypair_generation(self):
        """Tests that a keypair is generated correctly."""
        public_key, private_key = RSACipher.generate_keypair(keysize=1024)
        n, e = public_key
        n_priv, d = private_key

        self.assertEqual(n, n_priv)
        self.assertEqual(e, 65537)
        self.assertTrue(n.bit_length() >= 1023)

    def test_encrypt_decrypt_roundtrip(self):
        """Tests that encryption followed by decryption returns the original string."""
        rsa = RSACipher()
        public_key, private_key = RSACipher.generate_keypair(keysize=1024)
        
        plaintext = "RSA encryption is a cornerstone of digital security."
        ciphertext = rsa.encrypt(plaintext, public_key)
        decrypted = rsa.decrypt(ciphertext, private_key)
        
        self.assertEqual(plaintext, decrypted)

    def test_payload_limit(self):
        """Tests that payload exceeding the modulus raises a ValueError."""
        rsa = RSACipher()
        # Very small key for testing limit
        public_key, _ = RSACipher.generate_keypair(keysize=128)
        
        # Long string that will likely exceed 128 bits
        plaintext = "This string is definitely longer than 128 bits when converted to an integer payload."
        with self.assertRaises(ValueError):
            rsa.encrypt(plaintext, public_key)

    def test_miller_rabin(self):
        """Tests the primality testing accuracy."""
        known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 7919, 104729]
        known_composites = [4, 6, 8, 9, 10, 15, 21, 25, 7921] # 7921 = 89 * 89
        
        for p in known_primes:
            self.assertTrue(RSACipher._miller_rabin(p), f"Failed to identify {p} as prime")
            
        for c in known_composites:
            self.assertFalse(RSACipher._miller_rabin(c), f"Failed to identify {c} as composite")

if __name__ == "__main__":
    unittest.main()
