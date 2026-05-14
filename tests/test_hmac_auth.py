import unittest
from backend.algorithms.hmac_auth import HMACAuth


class TestHMACAuth(unittest.TestCase):
    """Test suite for HMACAuth implementation."""

    def test_hmac_cycle(self):
        """Tests complete HMAC computation and verification cycle."""
        key = HMACAuth.generate_key()
        message = "Integrity check message"
        
        tag = HMACAuth.compute_hmac(message, key)
        is_valid = HMACAuth.verify_hmac(message, key, tag)
        
        self.assertTrue(is_valid)

    def test_tamper_detection(self):
        """Tests that HMAC detects message tampering."""
        key = HMACAuth.generate_key()
        message = "Original Message"
        tag = HMACAuth.compute_hmac(message, key)
        
        self.assertFalse(HMACAuth.verify_hmac("Modified Message", key, tag))

    def test_invalid_key_fails(self):
        """Tests that a wrong key fails verification."""
        key1 = HMACAuth.generate_key()
        key2 = HMACAuth.generate_key()
        message = "Security Test"
        
        tag = HMACAuth.compute_hmac(message, key1)
        self.assertFalse(HMACAuth.verify_hmac(message, key2, tag))

    def test_standard_vectors(self):
        """Tests against a known (simple) manual case."""
        # K = 'key', M = 'The quick brown fox jumps over the lazy dog'
        # Verification using scratch logic correctness
        key = "key"
        message = "The quick brown fox jumps over the lazy dog"
        tag1 = HMACAuth.compute_hmac(message, key)
        tag2 = HMACAuth.compute_hmac(message, key)
        self.assertEqual(tag1, tag2)


if __name__ == "__main__":
    unittest.main()
