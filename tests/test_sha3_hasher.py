import unittest
from backend.algorithms.sha3_hasher import SHA3Hasher


class TestSHA3Hasher(unittest.TestCase):
    """Test suite for SHA3Hasher implementation."""

    def test_hash_256(self):
        """Tests SHA3-256 hashing."""
        data = "SHA3"
        h = SHA3Hasher.hash_256(data)
        # Length of SHA3-256 hex digest is 64 characters (256 bits)
        self.assertEqual(len(h), 64)
        # Deterministic check
        self.assertEqual(h, SHA3Hasher.hash_256(data))

    def test_hash_512(self):
        """Tests SHA3-512 hashing."""
        data = "Keccak"
        h = SHA3Hasher.hash_512(data)
        # Length is 128 characters (512 bits)
        self.assertEqual(len(h), 128)

    def test_different_outputs(self):
        """Tests that different lengths produce different digests."""
        data = "test"
        h256 = SHA3Hasher.hash_256(data)
        h512 = SHA3Hasher.hash_512(data)
        self.assertNotEqual(h256, h512)

    def test_bytes_input(self):
        """Tests that bytes input is handled correctly."""
        data = b"binary data"
        h = SHA3Hasher.hash_256(data)
        self.assertEqual(len(h), 64)


if __name__ == "__main__":
    unittest.main()
