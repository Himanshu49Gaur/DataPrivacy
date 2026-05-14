import base64
import struct
import hashlib
import binascii

class DESCipher:
    """
    A class to perform Data Encryption Standard (DES) Block Cipher operations.

    Disclaimer: DES (with its 56-bit key) is cryptographically broken and
    vulnerable to brute-force attacks, has been superseded by AES, and is
    implemented here in Electronic Codebook (ECB) mode strictly as a
    historical cryptographic primitive for educational and architectural
    demonstration.
    """

    # DES Standard Tables
    INITIAL_PERMUTATION = (
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    )

    FINAL_PERMUTATION = (
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    )

    EXPANSION_PERMUTATION = (
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    )

    PERMUTATION = (
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    )

    S_BOXES = (
        ( # S1
            (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
            (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
            (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
            (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
        ),
        ( # S2
            (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
            (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
            (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
            (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
        ),
        ( # S3
            (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
            (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
            (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
            (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
        ),
        ( # S4
            (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
            (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
            (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
            (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)
        ),
        ( # S5
            (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
            (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
            (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
            (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)
        ),
        ( # S6
            (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
            (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
            (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
            (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)
        ),
        ( # S7
            (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
            (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
            (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
            (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)
        ),
        ( # S8
            (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
            (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
            (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
            (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
        )
    )

    PC1 = (
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    )

    PC2 = (
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    )

    SHIFT_SCHEDULE = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

    @classmethod
    def validate_parameters(cls, key: str) -> bytes:
        """
        Validates the input key and hashes it to exactly 8 bytes (64 bits).

        Args:
            key (str): The input key string.

        Returns:
            bytes: The 8-byte key.

        Raises:
            ValueError: If the key is empty.
        """
        if not key:
            raise ValueError("Key cannot be empty.")
        # Use first 8 bytes of MD5 hash to ensure exactly 64 bits.
        return hashlib.md5(key.encode("utf-8")).digest()[:8]

    @classmethod
    def _pad(cls, data: bytes) -> bytes:
        """
        Applies PKCS#7 padding to align data to 8-byte blocks.

        Args:
            data (bytes): The bytes to pad.

        Returns:
            bytes: Padded bytes.
        """
        padding_len = 8 - (len(data) % 8)
        return data + bytes([padding_len] * padding_len)

    @classmethod
    def _unpad(cls, data: bytes) -> bytes:
        """
        Removes PKCS#7 padding from decoded data.

        Args:
            data (bytes): The padded bytes.

        Returns:
            bytes: Unpadded bytes.

        Raises:
            ValueError: If padding is mathematically invalid.
        """
        if not data:
            raise ValueError("Corrupted ciphertext: empty data.")
        padding_len = data[-1]
        if padding_len < 1 or padding_len > 8:
            raise ValueError("Corrupted ciphertext: invalid PKCS#7 padding length.")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Corrupted ciphertext: invalid PKCS#7 padding sequence.")
        return data[:-padding_len]

    def _permute(self, input_val: int, table: tuple[int, ...], input_len: int) -> int:
        """
        Helper to perform bitwise permutation.

        Args:
            input_val (int): The integer to permute.
            table (tuple[int, ...]): The permutation table.
            input_len (int): The length of the input in bits.

        Returns:
            int: The permuted integer.
        """
        output = 0
        for pos in table:
            output = (output << 1) | ((input_val >> (input_len - pos)) & 1)
        return output

    def _key_schedule(self, key: bytes) -> list[int]:
        """
        Generates 16 subkeys for the DES rounds.

        Args:
            key (bytes): The 8-byte master key.

        Returns:
            list[int]: A list of 16 48-bit subkey integers.
        """
        key_val = int.from_bytes(key, byteorder="big")
        # PC-1: 64 bits -> 56 bits
        permuted_key = self._permute(key_val, self.PC1, 64)
        
        c = (permuted_key >> 28) & 0xFFFFFFF
        d = permuted_key & 0xFFFFFFF
        
        subkeys = []
        for shift in self.SHIFT_SCHEDULE:
            # Circular left shift
            c = ((c << shift) & 0xFFFFFFF) | (c >> (28 - shift))
            d = ((d << shift) & 0xFFFFFFF) | (d >> (28 - shift))
            # PC-2: 56 bits -> 48 bits
            subkeys.append(self._permute((c << 28) | d, self.PC2, 56))
            
        return subkeys

    def _feistel_function(self, right_half: int, subkey: int) -> int:
        """
        The DES f function (non-linear transformation).

        Args:
            right_half (int): 32-bit right half of the block.
            subkey (int): 48-bit round subkey.

        Returns:
            int: 32-bit transformation result.
        """
        # Expansion E: 32 bits -> 48 bits
        expanded = self._permute(right_half, self.EXPANSION_PERMUTATION, 32)
        
        # XOR with subkey
        xor_result = expanded ^ subkey
        
        # S-box compression: 48 bits -> 32 bits
        s_output = 0
        for i in range(8):
            # Each S-box takes 6 bits
            chunk = (xor_result >> (42 - 6 * i)) & 0x3F
            row = ((chunk >> 4) & 0x02) | (chunk & 0x01)
            col = (chunk >> 1) & 0x0F
            s_val = self.S_BOXES[i][row][col]
            s_output = (s_output << 4) | s_val
            
        # Permutation P: 32 bits -> 32 bits
        return self._permute(s_output, self.PERMUTATION, 32)

    def _encrypt_block(self, block: bytes, subkeys: list[int]) -> bytes:
        """
        Encrypts a single 64-bit block.

        Args:
            block (bytes): 8 bytes of plaintext.
            subkeys (list[int]): 16 round subkeys.

        Returns:
            bytes: 8 bytes of ciphertext.
        """
        val = int.from_bytes(block, byteorder="big")
        # Initial Permutation
        val = self._permute(val, self.INITIAL_PERMUTATION, 64)
        
        l_half = (val >> 32) & 0xFFFFFFFF
        r_half = val & 0xFFFFFFFF
        
        for i in range(16):
            prev_l = l_half
            l_half = r_half
            r_half = (prev_l ^ self._feistel_function(r_half, subkeys[i])) & 0xFFFFFFFF
            
        # Final swap and combine
        combined = (r_half << 32) | l_half
        # Final Permutation
        final_val = self._permute(combined, self.FINAL_PERMUTATION, 64)
        
        return final_val.to_bytes(8, byteorder="big")

    def _decrypt_block(self, block: bytes, subkeys: list[int]) -> bytes:
        """
        Decrypts a single 64-bit block.

        Args:
            block (bytes): 8 bytes of ciphertext.
            subkeys (list[int]): 16 round subkeys.

        Returns:
            bytes: 8 bytes of plaintext.
        """
        # Decryption is encryption with subkeys in reverse order.
        return self._encrypt_block(block, subkeys[::-1])

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts a string using DES in ECB mode.

        Args:
            plaintext (str): The text to encrypt.
            key (str): The master key string.

        Returns:
            str: Base64 encoded ciphertext.
        """
        if not plaintext:
            return ""

        byte_key = self.validate_parameters(key)
        subkeys = self._key_schedule(byte_key)
        
        data = self._pad(plaintext.encode("utf-8"))
        ciphertext = bytearray()
        
        for i in range(0, len(data), 8):
            block = data[i : i + 8]
            ciphertext.extend(self._encrypt_block(block, subkeys))
            
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts a Base64 encoded string using DES in ECB mode.

        Args:
            ciphertext (str): Base64 encoded ciphertext.
            key (str): The master key string.

        Returns:
            str: Decrypted plaintext.

        Raises:
            ValueError: If input is invalid or padding is corrupted.
        """
        if not ciphertext:
            return ""

        byte_key = self.validate_parameters(key)
        subkeys = self._key_schedule(byte_key)
        
        try:
            data = base64.b64decode(ciphertext.encode("utf-8"))
        except (binascii.Error, ValueError) as e:
            raise ValueError("Corrupted ciphertext: invalid Base64 payload.") from e
            
        if not data or len(data) % 8 != 0:
            raise ValueError("Corrupted ciphertext: invalid block boundary.")
            
        plaintext_padded = bytearray()
        for i in range(0, len(data), 8):
            block = data[i : i + 8]
            plaintext_padded.extend(self._decrypt_block(block, subkeys))
            
        plaintext_bytes = self._unpad(bytes(plaintext_padded))
        return plaintext_bytes.decode("utf-8", errors="replace")
