import unittest
from backend.algorithms.lucifer_cipher import LuciferCipher

class TestLuciferCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = LuciferCipher()
        self.key = "SecretLuciferKey"

    def test_validate_parameters(self):
        byte_key = LuciferCipher.validate_parameters(self.key)
        self.assertEqual(len(byte_key), 16)
        with self.assertRaises(ValueError):
            LuciferCipher.validate_parameters("")

    def test_padding(self):
        data = b"Hello"
        padded = LuciferCipher._pad(data)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-11:], bytes([11] * 11))
        
        unpadded = LuciferCipher._unpad(padded)
        self.assertEqual(unpadded, data)

    def test_invalid_padding(self):
        # Last byte is 3, so it expects last 3 bytes to be \x03\x03\x03.
        # We provide a mismatched sequence.
        data = b"0123456789ABC\x01\x02\x03"
        with self.assertRaises(ValueError) as cm:
            LuciferCipher._unpad(data)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid PKCS#7 padding sequence.")
            
        # Invalid padding length (0 or > 16)
        data = b"0123456789ABCDE\x00"
        with self.assertRaises(ValueError) as cm:
            LuciferCipher._unpad(data)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid PKCS#7 padding length.")

    def test_encrypt_decrypt_identity(self):
        plaintext = "The quick brown fox jumps over the lazy dog."
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        decrypted = self.cipher.decrypt(ciphertext, self.key)
        self.assertEqual(decrypted, plaintext)

    def test_block_encryption_decryption(self):
        byte_key = self.cipher.validate_parameters(self.key)
        subkeys = self.cipher._key_schedule(byte_key)
        block = b"1234567890ABCDEF"
        
        encrypted = self.cipher._encrypt_block(block, subkeys)
        self.assertEqual(len(encrypted), 16)
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
        # Base64 of 15 bytes (invalid block size)
        invalid_ct = "MTIzNDU2Nzg5MEFCQ0RF" 
        with self.assertRaises(ValueError) as cm:
            self.cipher.decrypt(invalid_ct, self.key)
        self.assertEqual(str(cm.exception), "Corrupted ciphertext: invalid block boundary.")

if __name__ == "__main__":
    unittest.main()
