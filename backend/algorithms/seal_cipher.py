import base64
import hashlib
import struct
import binascii
from typing import Generator

class SEALCipher:
    """
    A class to perform SEAL (Software-Optimized Encryption Algorithm) Stream Cipher operations.

    Disclaimer: SEAL relies heavily on a 160-bit key and historically utilizes
    SHA-1 for its pseudo-random function during table initialization. It is
    considered a legacy cipher optimized for older 32-bit architectures and is
    implemented here strictly for advanced cryptographic education and
    architectural demonstration.
    """

    def __init__(self) -> None:
        """Initializes the SEAL cipher with internal state tables."""
        self.t: list[int] = []
        self.s: list[int] = []
        self.r: list[int] = []

    @classmethod
    def validate_parameters(cls, key: str, position: int) -> tuple[bytes, int]:
        """
        Validates the key and position parameters for the SEAL cipher.

        Args:
            key: The string key to be hashed to 160 bits.
            position: A 32-bit unsigned integer representing the starting index.

        Returns:
            A tuple containing the 20-byte key and validated position.

        Raises:
            ValueError: If position is not a valid 32-bit unsigned integer.
        """
        if not (0 <= position <= 0xFFFFFFFF):
            raise ValueError("Position must be a 32-bit unsigned integer.")
        
        # SEAL 3.0 requires a 160-bit key (20 bytes).
        key_bytes = hashlib.sha1(key.encode("utf-8")).digest()
        return key_bytes, position

    def _initialize_tables(self, key: bytes) -> None:
        """
        Populates internal state tables T, S, and R using a SHA-1 based PRF.

        Args:
            key: A 20-byte hashed key.
        """
        def g(k: bytes, i: int) -> int:
            """Pseudo-random function G as defined in the SEAL specification."""
            n_idx = i // 5
            r_idx = i % 5
            h = hashlib.sha1(k + struct.pack(">I", n_idx)).digest()
            words = struct.unpack(">5I", h)
            return words[r_idx]

        # Table T: 512 32-bit words
        self.t = [g(key, i) & 0xFFFFFFFF for i in range(512)]
        # Table S: 256 32-bit words
        self.s = [g(key, 0x1000 + i) & 0xFFFFFFFF for i in range(256)]
        # Table R: 16 32-bit words
        self.r = [g(key, 0x2000 + i) & 0xFFFFFFFF for i in range(16)]

    def _generate_keystream(self, position: int) -> Generator[bytes, None, None]:
        """
        Continuously yields raw keystream blocks in 16-byte segments.

        Args:
            position: The initial 32-bit unsigned integer position.

        Yields:
            16-byte blocks of keystream.
        """
        curr_n = position
        while True:
            # Initial register states
            a = (curr_n ^ self.r[0]) & 0xFFFFFFFF
            b = ((curr_n >> 8) ^ self.r[1]) & 0xFFFFFFFF
            c = ((curr_n >> 16) ^ self.r[2]) & 0xFFFFFFFF
            d = ((curr_n >> 24) ^ self.r[3]) & 0xFFFFFFFF

            for j in range(64):
                # Core SEAL 3.0 inner loop logic
                p = (a & 0x7FC) >> 2
                b = (b + self.t[p]) & 0xFFFFFFFF
                a = (((a >> 9) | (a << 23))) & 0xFFFFFFFF
                b = (b ^ a) & 0xFFFFFFFF

                q = (b & 0x7FC) >> 2
                c = (c ^ self.t[q]) & 0xFFFFFFFF
                b = (((b >> 9) | (b << 23))) & 0xFFFFFFFF
                c = (c + b) & 0xFFFFFFFF

                rr = (c & 0x7FC) >> 2
                d = (d + self.t[rr]) & 0xFFFFFFFF
                c = (((c >> 9) | (c << 23))) & 0xFFFFFFFF
                d = (d ^ c) & 0xFFFFFFFF

                ss = (d & 0x7FC) >> 2
                a = (a ^ self.t[ss]) & 0xFFFFFFFF
                d = (((d >> 9) | (d << 23))) & 0xFFFFFFFF
                a = (a + d) & 0xFFFFFFFF

                # Output keystream words
                w1 = (b + self.s[4 * j]) & 0xFFFFFFFF
                w2 = (c ^ self.s[4 * j + 1]) & 0xFFFFFFFF
                w3 = (d + self.s[4 * j + 2]) & 0xFFFFFFFF
                w4 = (a ^ self.s[4 * j + 3]) & 0xFFFFFFFF

                yield struct.pack(">4I", w1, w2, w3, w4)

                # Periodic update with R table every 16 iterations
                if (j + 1) % 16 == 0 and (j + 1) < 64:
                    idx = 4 * ((j + 1) // 16)
                    a = (a + self.r[idx]) & 0xFFFFFFFF
                    b = (b + self.r[idx + 1]) & 0xFFFFFFFF
                    c = (c + self.r[idx + 2]) & 0xFFFFFFFF
                    d = (d + self.r[idx + 3]) & 0xFFFFFFFF
            
            # Increment position for subsequent blocks
            curr_n = (curr_n + 1) & 0xFFFFFFFF

    def encrypt(self, plaintext: str, key: str, position: int = 0) -> str:
        """
        Encrypts a plaintext string using the SEAL algorithm.

        Args:
            plaintext: The input string to encrypt.
            key: The encryption key.
            position: Optional starting position.

        Returns:
            A Base64 encoded ciphertext string.

        Raises:
            ValueError: If inputs are invalid.
        """
        if not plaintext:
            return ""

        key_bytes, pos = self.validate_parameters(key, position)
        self._initialize_tables(key_bytes)
        
        pt_bytes = plaintext.encode("utf-8")
        keystream = self._generate_keystream(pos)
        ct_bytes = bytearray()
        
        # Keystream is processed in 16-byte blocks
        stream_ptr = 0
        current_block = b""
        
        for byte in pt_bytes:
            if stream_ptr == 0:
                current_block = next(keystream)
            
            ct_bytes.append(byte ^ current_block[stream_ptr])
            stream_ptr = (stream_ptr + 1) % 16
            
        return base64.b64encode(ct_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str, position: int = 0) -> str:
        """
        Decrypts a Base64 encoded ciphertext string using the SEAL algorithm.

        Args:
            ciphertext: The Base64 encoded string to decrypt.
            key: The encryption key.
            position: The starting position used during encryption.

        Returns:
            The decrypted plaintext string.

        Raises:
            ValueError: If input is invalid or ciphertext is corrupted.
        """
        if not ciphertext:
            return ""

        key_bytes, pos = self.validate_parameters(key, position)
        self._initialize_tables(key_bytes)
        
        try:
            ct_bytes = base64.b64decode(ciphertext.encode("utf-8"))
        except (ValueError, binascii.Error) as e:
            raise ValueError("Corrupted ciphertext: invalid Base64 payload.") from e
            
        keystream = self._generate_keystream(pos)
        pt_bytes = bytearray()
        
        stream_ptr = 0
        current_block = b""
        
        for byte in ct_bytes:
            if stream_ptr == 0:
                current_block = next(keystream)
            
            pt_bytes.append(byte ^ current_block[stream_ptr])
            stream_ptr = (stream_ptr + 1) % 16
            
        return pt_bytes.decode("utf-8", errors="replace")
