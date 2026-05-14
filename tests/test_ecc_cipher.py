import unittest
from backend.algorithms.ecc_cipher import ECCCipher


class TestECCCipher(unittest.TestCase):
    """Test suite for ECCCipher implementation."""

    def test_key_exchange_success(self):
        """Tests a complete ECDH key exchange between two parties."""
        ecc_alice = ECCCipher()
        ecc_bob = ECCCipher()

        # Alice generates keys
        alice_private, alice_public = ecc_alice.generate_keypair()

        # Bob generates keys
        bob_private, bob_public = ecc_bob.generate_keypair()

        # Alice computes shared secret using Bob's public key
        alice_secret = ecc_alice.compute_shared_secret(alice_private, bob_public)

        # Bob computes shared secret using Alice's public key
        bob_secret = ecc_bob.compute_shared_secret(bob_private, alice_public)

        # Secrets must match
        self.assertEqual(alice_secret, bob_secret)
        self.assertTrue(len(alice_secret) > 0)

    def test_point_on_curve(self):
        """Tests if generated public keys are on the secp256k1 curve."""
        ecc = ECCCipher()
        _, (x, y) = ecc.generate_keypair()

        # Verify y^2 = x^3 + 7 (mod P)
        left_side = (y * y) % ecc.P
        right_side = (pow(x, 3, ecc.P) + 7) % ecc.P

        self.assertEqual(left_side, right_side)

    def test_deterministic_shared_secret(self):
        """Tests that the same keys always produce the same secret."""
        ecc = ECCCipher()
        alice_private, _ = ecc.generate_keypair()
        _, bob_public = ecc.generate_keypair()

        secret1 = ecc.compute_shared_secret(alice_private, bob_public)
        secret2 = ecc.compute_shared_secret(alice_private, bob_public)

        self.assertEqual(secret1, secret2)

    def test_scalar_mult_infinity(self):
        """Tests multiplication by curve order N results in infinity."""
        ecc = ECCCipher()
        result = ecc._scalar_mult(ecc.N, ecc.G)
        self.assertIsNone(result)

    def test_scalar_mult_one(self):
        """Tests multiplication by 1 results in the same point."""
        ecc = ECCCipher()
        result = ecc._scalar_mult(1, ecc.G)
        self.assertEqual(result, ecc.G)


if __name__ == "__main__":
    unittest.main()
