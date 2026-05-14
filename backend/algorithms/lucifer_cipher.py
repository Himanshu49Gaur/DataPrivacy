import base64
import struct
import hashlib
import binascii

class LuciferCipher:
    """
    A class to perform Lucifer Block Cipher operations.

    Disclaimer: Lucifer is the historical predecessor to DES, is vulnerable to
    differential cryptanalysis, and is implemented here exclusively in Electronic
    Codebook (ECB) mode as an advanced cryptographic primitive for educational
    and architectural demonstration.
    """

    # 4x4 S-boxes (4-bit to 4-bit substitution)
    S0 = (12, 15, 7, 10, 14, 13, 11, 0, 2, 6, 3, 1, 9, 4, 5, 8)
    S1 = (7, 2, 14, 9, 3, 11, 0, 4, 12, 13, 1, 10, 6, 15, 8, 5)

    # 64-bit Bit-Permutation Table P
    P = (
        7, 48, 16, 40, 56, 32, 24, 8,
        0, 49, 17, 41, 57, 33, 25, 9,
        1, 50, 18, 42, 58, 34, 26, 10,
        2, 51, 19, 43, 59, 35, 27, 11,
        3, 52, 20, 44, 60, 36, 28, 12,
        4, 53, 21, 45, 61, 37, 29, 13,
        5, 54, 22, 46, 62, 38, 30, 14,
        6, 55, 23, 47, 63, 39, 31, 15
    )

    @classmethod
    def validate_parameters(cls, key: str) -> bytes:
        """
        Validates the key and ensures it is exactly 128 bits (16 bytes).

        Args:
            key (str): The string key to validate.

        Returns:
            bytes: A 16-byte key derived from hashing the input.

        Raises:
            ValueError: If the key is empty.
        """
        if not key:
            raise ValueError("Key cannot be empty.")
        return hashlib.md5(key.encode("utf-8")).digest()

    @classmethod
    def _pad(cls, data: bytes) -> bytes:
        """
        Applies PKCS#7 padding to align data to 16-byte blocks.

        Args:
            data (bytes): The raw bytes to pad.

        Returns:
            bytes: Padded bytes.
        """
        padding_len = 16 - (len(data) % 16)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @classmethod
    def _unpad(cls, data: bytes) -> bytes:
        """
        Removes PKCS#7 padding from decoded data.

        Args:
            data (bytes): The padded bytes.

        Returns:
            bytes: Unpadded raw bytes.

        Raises:
            ValueError: If padding is invalid or corrupted.
        """
        if not data:
            raise ValueError("Corrupted ciphertext: empty data.")
        padding_len = data[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Corrupted ciphertext: invalid PKCS#7 padding length.")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Corrupted ciphertext: invalid PKCS#7 padding sequence.")
        return data[:-padding_len]

    def _key_schedule(self, key: bytes) -> list[bytes]:
        """
        Expands the 128-bit key into 16 subkeys using cyclic shifts.

        Args:
            key (bytes): The 16-byte master key.

        Returns:
            list[bytes]: A list of 16 subkeys, each 16 bytes.
        """
        subkeys = []
        key_int = int.from_bytes(key, byteorder="big")
        for i in range(16):
            # Cyclic shift by 3 bits each round
            shift = (i * 3) % 128
            rotated = ((key_int << shift) & ((1 << 128) - 1)) | (key_int >> (128 - shift))
            subkeys.append(rotated.to_bytes(16, byteorder="big"))
        return subkeys

    def _feistel_function(self, right_half: bytes, subkey: bytes) -> bytes:
        """
        Core non-linear function for the Lucifer Feistel network.

        Args:
            right_half (bytes): 8 bytes (64 bits) of data.
            subkey (bytes): 16 bytes (128 bits) of subkey.

        Returns:
            bytes: 8 bytes of processed output.
        """
        # XOR first 8 bytes of subkey with right_half
        xor_result = bytes(a ^ b for a, b in zip(right_half, subkey[:8]))

        # S-box substitution with selector bits from subkey[8:10]
        selector = int.from_bytes(subkey[8:10], byteorder="big")
        substituted = bytearray()
        
        for i in range(8):
            byte = xor_result[i]
            # High nibble (bits 7-4)
            nibble_h = (byte >> 4) & 0x0F
            s_box_h = self.S1 if (selector >> (2 * i + 1)) & 1 else self.S0
            val_h = s_box_h[nibble_h]
            
            # Low nibble (bits 3-0)
            nibble_l = byte & 0x0F
            s_box_l = self.S1 if (selector >> (2 * i)) & 1 else self.S0
            val_l = s_box_l[nibble_l]
            
            substituted.append((val_h << 4) | val_l)

        # Bit Permutation P (64 bits)
        substituted_int = int.from_bytes(substituted, byteorder="big")
        permuted_int = 0
        for i, target_pos in enumerate(self.P):
            if (substituted_int >> (63 - i)) & 1:
                permuted_int |= (1 << (63 - target_pos))
        
        return permuted_int.to_bytes(8, byteorder="big")

    def _encrypt_block(self, block: bytes, subkeys: list[bytes]) -> bytes:
        """
        Encrypts a single 128-bit block using 16 rounds.

        Args:
            block (bytes): 16 bytes of plaintext.
            subkeys (list[bytes]): 16 expansion subkeys.

        Returns:
            bytes: 16 bytes of ciphertext.
        """
        left = block[:8]
        right = block[8:]
        
        for i in range(16):
            f_out = self._feistel_function(right, subkeys[i])
            new_right = bytes(a ^ b for a, b in zip(left, f_out))
            left = right
            right = new_right
            
        # Final swap for reciprocity
        return right + left

    def _decrypt_block(self, block: bytes, subkeys: list[bytes]) -> bytes:
        """
        Decrypts a single 128-bit block by reversing the Feistel network.

        Args:
            block (bytes): 16 bytes of ciphertext.
            subkeys (list[bytes]): 16 expansion subkeys.

        Returns:
            bytes: 16 bytes of plaintext.
        """
        left = block[:8]
        right = block[8:]
        
        # Apply subkeys in reverse order
        for i in range(15, -1, -1):
            f_out = self._feistel_function(right, subkeys[i])
            new_right = bytes(a ^ b for a, b in zip(left, f_out))
            left = right
            right = new_right
            
        return right + left

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts a plaintext string using Lucifer in ECB mode.

        Args:
            plaintext (str): Input text.
            key (str): Master key string.

        Returns:
            str: Base64 encoded ciphertext.
        """
        if not plaintext:
            return ""

        byte_key = self.validate_parameters(key)
        subkeys = self._key_schedule(byte_key)
        
        data = self._pad(plaintext.encode("utf-8"))
        ciphertext = bytearray()
        
        for i in range(0, len(data), 16):
            block = data[i : i + 16]
            ciphertext.extend(self._encrypt_block(block, subkeys))
            
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts a Base64 encoded ciphertext string.

        Args:
            ciphertext (str): Base64 encoded ciphertext.
            key (str): Master key string.

        Returns:
            str: Decrypted plaintext.

        Raises:
            ValueError: If decryption or unpadding fails.
        """
        if not ciphertext:
            return ""

        byte_key = self.validate_parameters(key)
        subkeys = self._key_schedule(byte_key)
        
        try:
            data = base64.b64decode(ciphertext.encode("utf-8"))
        except (ValueError, binascii.Error) as e:
            raise ValueError("Corrupted ciphertext: invalid Base64 payload.") from e
            
        if not data or len(data) % 16 != 0:
            raise ValueError("Corrupted ciphertext: invalid block boundary.")
            
        plaintext_padded = bytearray()
        for i in range(0, len(data), 16):
            block = data[i : i + 16]
            plaintext_padded.extend(self._decrypt_block(block, subkeys))
            
        plaintext_bytes = self._unpad(bytes(plaintext_padded))
        return plaintext_bytes.decode("utf-8", errors="replace")
