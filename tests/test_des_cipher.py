import unittest
from backend.algorithms.des_cipher import DESCipher

class TestDESCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = DESCipher()
        self.key = "SecretDESKey"

    def test_validate_parameters(self):
        byte_key = DESCipher.validate_parameters(self.key)
        self.assertEqual(len(byte_key), 8)
        with self.assertRaises(ValueError):
            DESCipher.validate_parameters("")

    def test_padding(self):
        data = b"Hello"
        padded = DESCipher._pad(data)
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded[-3:], bytes([3] * 3))
        
        unpadded = DESCipher._unpad(padded)
        self.assertEqual(unpadded, data)

    def test_invalid_padding(self):
        # Mismatched sequence
        data = b"12345\x01\x02\x03"
        with self.assertRaises(ValueError) as cm:
            DESCipher._unpad(data)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid PKCS#7 padding sequence.")
            
        # Invalid padding length
        data = b"1234567\x00"
        with self.assertRaises(ValueError) as cm:
            DESCipher._unpad(data)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid PKCS#7 padding length.")

    def test_encrypt_decrypt_identity(self):
        plaintext = "The quick brown fox jumps over the lazy dog."
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        decrypted = self.cipher.decrypt(ciphertext, self.key)
        self.assertEqual(decrypted, plaintext)

    def test_block_encryption_decryption(self):
        byte_key = self.cipher.validate_parameters(self.key)
        subkeys = self.cipher._key_schedule(byte_key)
        block = b"8byteblk"
        
        encrypted = self.cipher._encrypt_block(block, subkeys)
        self.assertEqual(len(encrypted), 8)
        self.assertNotEqual(encrypted, block)
        
        decrypted = self.cipher._decrypt_block(encrypted, subkeys)
        self.assertEqual(decrypted, block)

    def test_empty_input(self):
        self.assertEqual(self.cipher.encrypt("", self.key), "")
        self.assertEqual(self.cipher.decrypt("", self.key), "")

    def test_corrupted_base64(self):
        with self.assertRaises(ValueError):
            self.cipher.decrypt("!!!NotBase64!!!", self.key)

    def test_invalid_block_boundary(self):
        # Base64 of 7 bytes (invalid block size)
        invalid_ct = "MTIzNDU2Nw==" 
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt(invalid_ct, self.key)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid block boundary.")

if __name__ == "__main__":
    unittest.main()
