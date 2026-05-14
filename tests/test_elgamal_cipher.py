import unittest
from backend.algorithms.elgamal_cipher import ElGamalCipher


class TestElGamalCipher(unittest.TestCase):
    """Test suite for the ElGamalCipher implementation."""

    def test_keypair_generation(self):
        """Tests that a keypair is generated correctly."""
        elgamal = ElGamalCipher()
        public_key, private_key = elgamal.generate_keypair()
        
        p, g, y = public_key
        p_priv, g_priv, x = private_key

        self.assertEqual(p, p_priv)
        self.assertEqual(g, g_priv)
        self.assertEqual(p, ElGamalCipher.RFC_3526_2048_PRIME)
        self.assertTrue(1 < x < p)
        self.assertEqual(y, pow(g, x, p))

    def test_encrypt_decrypt_roundtrip(self):
        """Tests that encryption followed by decryption returns the original string."""
        elgamal = ElGamalCipher()
        public_key, private_key = elgamal.generate_keypair()
        
        plaintext = "ElGamal encryption is based on the Diffie-Hellman key exchange."
        ciphertext = elgamal.encrypt(plaintext, public_key)
        decrypted = elgamal.decrypt(ciphertext, private_key)
        
        self.assertEqual(plaintext, decrypted)

    def test_payload_limit(self):
        """Tests that payload exceeding the group prime raises a ValueError."""
        # Using a very small prime for testing limit
        small_prime = 257
        elgamal = ElGamalCipher(prime=small_prime)
        public_key, _ = elgamal.generate_keypair()
        
        # Long string that will definitely exceed 257 as an integer
        plaintext = "This string is much larger than 257."
        with self.assertRaises(ValueError):
            elgamal.encrypt(plaintext, public_key)

    def test_custom_group(self):
        """Tests the logic with a custom small prime group."""
        p = 7919
        g = 2
        elgamal = ElGamalCipher(prime=p, generator=g)
        public_key, private_key = elgamal.generate_keypair()
        
        # 'A' is 65, which is < 7919
        plaintext = "A"
        ciphertext = elgamal.encrypt(plaintext, public_key)
        decrypted = elgamal.decrypt(ciphertext, private_key)
        
        self.assertEqual(plaintext, decrypted)


if __name__ == "__main__":
    unittest.main()
