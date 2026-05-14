import unittest
from backend.algorithms.ecdh_cipher import ECDHCipher


class TestECDHCipher(unittest.TestCase):
    """Test suite for ECDHCipher implementation."""

    def test_key_exchange_success(self):
        """Tests a complete ECDH key agreement between two parties."""
        ecdh_alice = ECDHCipher()
        ecdh_bob = ECDHCipher()

        # Generate keypairs
        alice_priv, alice_pub = ecdh_alice.generate_keypair()
        bob_priv, bob_pub = ecdh_bob.generate_keypair()

        # Compute shared secrets
        alice_shared = ecdh_alice.compute_shared_secret(alice_priv, bob_pub)
        bob_shared = ecdh_bob.compute_shared_secret(bob_priv, alice_pub)

        # Secrets must match
        self.assertEqual(alice_shared, bob_shared)
        self.assertTrue(len(alice_shared) > 0)

    def test_invalid_peer_public_key(self):
        """Tests that invalid public keys raise ValueError."""
        ecdh = ECDHCipher()
        priv, _ = ecdh.generate_keypair()
        
        # Invalid point (not on curve)
        invalid_pub = (1, 1)
        with self.assertRaises(ValueError) as cm:
            ecdh.compute_shared_secret(priv, invalid_pub)
        self.assertIn("not a valid point", str(cm.exception))

    def test_shared_point_at_infinity(self):
        """Tests handling of shared point at infinity (though rare with valid keys)."""
        ecdh = ECDHCipher()
        priv, _ = ecdh.generate_keypair()
        
        # Identity point or invalid multiplication that results in None
        # We can't easily trigger None with valid keys, but we can mock or use N
        # If Alice uses N as private key (which is invalid in our gen), she'd get infinity
        with self.assertRaises(ValueError):
            # private key N results in scalar mult being None (if logic allowed)
            # In our implementation we handle it in mult
            ecdh.compute_shared_secret(ecdh.N, ecdh.G)

    def test_point_on_curve_validation(self):
        """Tests the point-on-curve mathematical validation."""
        ecdh = ECDHCipher()
        _, pub = ecdh.generate_keypair()
        x, y = pub
        
        # Should not raise
        ecdh.compute_shared_secret(1, pub)

    def test_deterministic_kdf(self):
        """Tests that the same shared point always yields the same derived secret."""
        ecdh = ECDHCipher()
        priv, pub = ecdh.generate_keypair()
        
        secret1 = ecdh.compute_shared_secret(priv, pub)
        secret2 = ecdh.compute_shared_secret(priv, pub)
        
        self.assertEqual(secret1, secret2)


if __name__ == "__main__":
    unittest.main()
