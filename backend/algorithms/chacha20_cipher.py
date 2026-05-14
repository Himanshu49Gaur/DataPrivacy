import struct
import base64


class ChaCha20Cipher:
    """
    A highly optimized, RFC 8439 compliant software implementation of ChaCha20.

    This module utilizes pure-Python ARX (Addition-Rotation-XOR) transformations
    to implement the ChaCha20 stream cipher with a 256-bit key and 96-bit nonce.
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
    def _quarter_round(cls, state: list[int], a: int, b: int, c: int, d: int) -> None:
        """
        Perform the ChaCha20 quarter-round operation on the state array.

        Args:
            state: The 16-word state array.
            a, b, c, d: Indices in the state array to operate on.
        """
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = cls._rotl(state[d], 16)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = cls._rotl(state[b], 12)

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = cls._rotl(state[d], 8)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = cls._rotl(state[b], 7)

    @classmethod
    def _chacha20_block(cls, key: bytes, counter: int, nonce: bytes) -> bytes:
        """
        Generate a single 64-byte ChaCha20 keystream block.

        Args:
            key: 32-byte encryption key.
            counter: 32-bit block counter.
            nonce: 12-byte nonce.

        Returns:
            64-byte keystream block.

        Raises:
            ValueError: If key or nonce length is incorrect.
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")

        key_words = struct.unpack("<8I", key)
        nonce_words = struct.unpack("<3I", nonce)

        # Initial state: 4 constants, 8 key words, 1 counter, 3 nonce words
        state = list(cls.MAGIC_CONSTANTS) + list(key_words) + [counter & 0xFFFFFFFF] + list(nonce_words)
        working_state = list(state)

        # 10 double-rounds (20 rounds total)
        for _ in range(10):
            # Column rounds
            cls._quarter_round(working_state, 0, 4, 8, 12)
            cls._quarter_round(working_state, 1, 5, 9, 13)
            cls._quarter_round(working_state, 2, 6, 10, 14)
            cls._quarter_round(working_state, 3, 7, 11, 15)
            # Diagonal rounds
            cls._quarter_round(working_state, 0, 5, 10, 15)
            cls._quarter_round(working_state, 1, 6, 11, 12)
            cls._quarter_round(working_state, 2, 7, 8, 13)
            cls._quarter_round(working_state, 3, 4, 9, 14)

        # Add original state to working state
        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

        return struct.pack("<16I", *working_state)

    def encrypt(self, plaintext: str, key: bytes, nonce: bytes, initial_counter: int = 1) -> str:
        """
        Encrypt plaintext using the ChaCha20 stream cipher.

        Args:
            plaintext: UTF-8 string to encrypt.
            key: 32-byte key.
            nonce: 12-byte nonce.
            initial_counter: Starting block counter (default 1).

        Returns:
            Base64 encoded ciphertext.
        """
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = bytearray()

        for i in range(0, len(plaintext_bytes), 64):
            block_index = i // 64
            keystream = self._chacha20_block(key, initial_counter + block_index, nonce)
            
            chunk = plaintext_bytes[i : i + 64]
            for j in range(len(chunk)):
                ciphertext.append(chunk[j] ^ keystream[j])

        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str, key: bytes, nonce: bytes, initial_counter: int = 1) -> str:
        """
        Decrypt ciphertext using the ChaCha20 stream cipher.

        Args:
            ciphertext: Base64 encoded ciphertext.
            key: 32-byte key.
            nonce: 12-byte nonce.
            initial_counter: Starting block counter (default 1).

        Returns:
            Decrypted UTF-8 string.
        """
        ciphertext_bytes = base64.b64decode(ciphertext)
        plaintext = bytearray()

        for i in range(0, len(ciphertext_bytes), 64):
            block_index = i // 64
            keystream = self._chacha20_block(key, initial_counter + block_index, nonce)
            
            chunk = ciphertext_bytes[i : i + 64]
            for j in range(len(chunk)):
                plaintext.append(chunk[j] ^ keystream[j])

        return plaintext.decode("utf-8")
