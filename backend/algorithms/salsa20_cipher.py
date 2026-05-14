import struct
import base64


class Salsa20Cipher:
    """
    A highly optimized, pure-Python software implementation of Salsa20/20.

    This module implements the standard Salsa20 stream cipher with a 256-bit key,
    64-bit nonce, and 64-bit block counter, utilizing 32-bit ARX transformations.
    """

    MAGIC_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @classmethod
    def _rotl(cls, x: int, n: int) -> int:
        """
        Perform a 32-bit left bitwise rotation.

        Args:
            x: The 32-bit integer to rotate.
            n: The number of bits to rotate.

        Returns:
            The rotated 32-bit integer.
        """
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    @classmethod
    def _quarter_round(cls, state: list[int], y0: int, y1: int, y2: int, y3: int) -> None:
        """
        Perform the Salsa20 quarter-round operation on the state array.

        Args:
            state: The 16-word state array.
            y0, y1, y2, y3: Indices in the state array to operate on.
        """
        state[y1] ^= cls._rotl((state[y0] + state[y3]) & 0xFFFFFFFF, 7)
        state[y2] ^= cls._rotl((state[y1] + state[y0]) & 0xFFFFFFFF, 9)
        state[y3] ^= cls._rotl((state[y2] + state[y1]) & 0xFFFFFFFF, 13)
        state[y0] ^= cls._rotl((state[y3] + state[y2]) & 0xFFFFFFFF, 18)

    @classmethod
    def _salsa20_block(cls, key: bytes, counter: int, nonce: bytes) -> bytes:
        """
        Generate a single 64-byte Salsa20 keystream block.

        Args:
            key: 32-byte encryption key.
            counter: 64-bit block counter.
            nonce: 8-byte nonce.

        Returns:
            64-byte keystream block.

        Raises:
            ValueError: If key or nonce length is incorrect.
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 8:
            raise ValueError("Nonce must be 8 bytes")

        k = struct.unpack("<8I", key)
        n = struct.unpack("<2I", nonce)
        c_low = counter & 0xFFFFFFFF
        c_high = (counter >> 32) & 0xFFFFFFFF

        # Diagonal layout:
        # [ c0 k0 k1 k2 ]
        # [ k3 c1 n0 n1 ]
        # [ i0 i1 c2 k4 ]
        # [ k5 k6 k7 c3 ]
        state = [
            cls.MAGIC_CONSTANTS[0], k[0], k[1], k[2],
            k[3], cls.MAGIC_CONSTANTS[1], n[0], n[1],
            c_low, c_high, cls.MAGIC_CONSTANTS[2], k[4],
            k[5], k[6], k[7], cls.MAGIC_CONSTANTS[3]
        ]

        working_state = list(state)

        # 10 double-rounds (20 rounds total)
        for _ in range(10):
            # Column rounds
            cls._quarter_round(working_state, 0, 4, 8, 12)
            cls._quarter_round(working_state, 5, 9, 13, 1)
            cls._quarter_round(working_state, 10, 14, 2, 6)
            cls._quarter_round(working_state, 15, 3, 7, 11)
            # Row rounds
            cls._quarter_round(working_state, 0, 1, 2, 3)
            cls._quarter_round(working_state, 5, 6, 7, 4)
            cls._quarter_round(working_state, 10, 11, 8, 9)
            cls._quarter_round(working_state, 15, 12, 13, 14)

        # Add original state to working state
        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

        return struct.pack("<16I", *working_state)

    def encrypt(self, plaintext: str, key: bytes, nonce: bytes, initial_counter: int = 0) -> str:
        """
        Encrypt plaintext using the Salsa20 stream cipher.

        Args:
            plaintext: UTF-8 string to encrypt.
            key: 32-byte key.
            nonce: 8-byte nonce.
            initial_counter: Starting block counter (default 0).

        Returns:
            Base64 encoded ciphertext.
        """
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = bytearray()

        for i in range(0, len(plaintext_bytes), 64):
            block_index = i // 64
            keystream = self._salsa20_block(key, initial_counter + block_index, nonce)

            chunk = plaintext_bytes[i : i + 64]
            for j in range(len(chunk)):
                ciphertext.append(chunk[j] ^ keystream[j])

        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str, key: bytes, nonce: bytes, initial_counter: int = 0) -> str:
        """
        Decrypt ciphertext using the Salsa20 stream cipher.

        Args:
            ciphertext: Base64 encoded ciphertext.
            key: 32-byte key.
            nonce: 8-byte nonce.
            initial_counter: Starting block counter (default 0).

        Returns:
            Decrypted UTF-8 string.
        """
        ciphertext_bytes = base64.b64decode(ciphertext)
        plaintext = bytearray()

        for i in range(0, len(ciphertext_bytes), 64):
            block_index = i // 64
            keystream = self._salsa20_block(key, initial_counter + block_index, nonce)

            chunk = ciphertext_bytes[i : i + 64]
            for j in range(len(chunk)):
                plaintext.append(chunk[j] ^ keystream[j])

        return plaintext.decode("utf-8")
