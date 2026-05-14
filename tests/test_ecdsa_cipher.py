import unittest
from backend.algorithms.ecdsa_cipher import ECDSACipher


class TestECDSACipher(unittest.TestCase):
    """Test suite for ECDSACipher implementation."""

    def test_signature_cycle(self):
        """Tests a complete signing and verification cycle."""
        ecdsa = ECDSACipher()
        priv, pub = ecdsa.generate_keypair()
        message = "Test message for ECDSA"

        signature = ecdsa.sign(message, priv)
        is_valid = ecdsa.verify(message, signature, pub)

        self.assertTrue(is_valid)

    def test_invalid_signature(self):
        """Tests that an invalid signature fails verification."""
        ecdsa = ECDSACipher()
        priv, pub = ecdsa.generate_keypair()
        message = "Test message"
        signature = ecdsa.sign(message, priv)

        # Modify message
        self.assertFalse(ecdsa.verify("Different message", signature, pub))

        # Modify signature (valid Base64 but wrong data)
        invalid_sig = "A" * 88  # 64 bytes in Base64
        self.assertFalse(ecdsa.verify(message, invalid_sig, pub))

    def test_signature_range(self):
        """Tests that r and s are within [1, N-1]."""
        ecdsa = ECDSACipher()
        priv, _ = ecdsa.generate_keypair()
        import base64
        
        signature = ecdsa.sign("Message", priv)
        sig_bytes = base64.b64decode(signature)
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")

        self.assertTrue(1 <= r < ecdsa.N)
        self.assertTrue(1 <= s < ecdsa.N)

    def test_public_key_on_curve(self):
        """Tests if the generated public key point is on the secp256k1 curve."""
        ecdsa = ECDSACipher()
        _, (x, y) = ecdsa.generate_keypair()

        # y^2 = x^3 + 7 (mod P)
        left = (y * y) % ecdsa.P
        right = (pow(x, 3, ecdsa.P) + 7) % ecdsa.P

        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
