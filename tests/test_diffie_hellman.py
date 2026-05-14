import unittest
from backend.algorithms.diffie_hellman import DiffieHellman


class TestDiffieHellman(unittest.TestCase):
    """Test suite for DiffieHellman implementation."""

    def test_key_exchange_success(self):
        """Tests a complete key exchange between two parties."""
        dh_alice = DiffieHellman()
        dh_bob = DiffieHellman()

        # Alice generates keys
        alice_private = dh_alice.generate_private_key()
        alice_public = dh_alice.generate_public_key(alice_private)

        # Bob generates keys
        bob_private = dh_bob.generate_private_key()
        bob_public = dh_bob.generate_public_key(bob_private)

        # Alice computes shared secret using Bob's public key
        alice_secret = dh_alice.compute_shared_secret(alice_private, bob_public)

        # Bob computes shared secret using Alice's public key
        bob_secret = dh_bob.compute_shared_secret(bob_private, alice_public)

        # Secrets must match
        self.assertEqual(alice_secret, bob_secret)
        self.assertTrue(len(alice_secret) > 0)

    def test_invalid_private_key(self):
        """Tests that invalid private keys raise errors."""
        dh = DiffieHellman()
        with self.assertRaises(ValueError):
            dh.generate_public_key(1)  # Too small
        with self.assertRaises(ValueError):
            dh.generate_public_key(dh.prime)  # Too large
        with self.assertRaises(TypeError):
            dh.generate_public_key("invalid")

    def test_invalid_peer_public_key(self):
        """Tests that invalid peer public keys raise errors."""
        dh = DiffieHellman()
        priv = dh.generate_private_key()
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(priv, 1)
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(priv, dh.prime)

    def test_custom_prime_generator(self):
        """Tests that custom primes and generators work for smaller values."""
        # Using a smaller prime for faster testing (though not recommended for production)
        small_prime = 7919
        small_gen = 7
        dh = DiffieHellman(prime=small_prime, generator=small_gen)
        
        priv = dh.generate_private_key()
        pub = dh.generate_public_key(priv)
        
        self.assertTrue(1 < priv < small_prime)
        self.assertEqual(pub, pow(small_gen, priv, small_prime))


if __name__ == "__main__":
    unittest.main()
