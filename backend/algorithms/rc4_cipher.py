import base64
import binascii
from typing import Generator

class RC4Cipher:
    """
    A class to perform RC4 Stream Cipher operations.

    Disclaimer: While RC4 is a foundational stream cipher, it is considered
    cryptographically broken for modern secure communications and is
    implemented here for educational and architectural demonstration.

    This class provides methods to validate a key, initialize the state
    using KSA, generate a keystream using PRGA, and perform encryption
    and decryption.
    """

    @classmethod
    def validate_key(cls, key: str) -> bytes:
        """
        Validates the provided key and converts it to bytes.

        Args:
            key (str): The key string to validate.

        Returns:
            bytes: The UTF-8 byte representation of the key.

        Raises:
            ValueError: If the key is empty.
        """
        if not key:
            raise ValueError("Key cannot be empty.")
        return key.encode("utf-8")

    def _ksa(self, key: bytes) -> list[int]:
        """
        Initializes the state array S using the Key-Scheduling Algorithm (KSA).

        Args:
            key (bytes): The validated byte key.

        Returns:
            list[int]: The scrambled state array S.
        """
        state_array = list(range(256))
        j = 0
        key_length = len(key)
        for i in range(256):
            j = (j + state_array[i] + key[i % key_length]) % 256
            state_array[i], state_array[j] = state_array[j], state_array[i]
        return state_array

    def _prga(self, state_array: list[int]) -> Generator[int, None, None]:
        """
        Generates a keystream using the Pseudo-Random Generation Algorithm (PRGA).

        Args:
            state_array (list[int]): The initialized state array S.

        Yields:
            int: The next byte in the pseudo-random keystream.
        """
        i = 0
        j = 0
        # Create a local copy to avoid modifying the input array if reused
        s = state_array[:]
        while True:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            yield s[(s[i] + s[j]) % 256]

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts plaintext using the RC4 algorithm.

        Args:
            plaintext (str): The text to be encrypted.
            key (str): The encryption key.

        Returns:
            str: Base64 encoded ciphertext string.

        Raises:
            ValueError: If the key validation fails.
        """
        if not plaintext:
            return ""

        byte_key = self.validate_key(key)
        plaintext_bytes = plaintext.encode("utf-8")
        
        state_array = self._ksa(byte_key)
        keystream = self._prga(state_array)
        
        ciphertext_bytes = bytearray()
        for char_byte in plaintext_bytes:
            ciphertext_bytes.append(char_byte ^ next(keystream))
            
        return base64.b64encode(ciphertext_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts Base64 encoded ciphertext using the RC4 algorithm.

        Args:
            ciphertext (str): The Base64 encoded ciphertext.
            key (str): The decryption key.

        Returns:
            str: Decrypted plaintext string.

        Raises:
            ValueError: If the key validation fails or ciphertext is corrupted.
        """
        if not ciphertext:
            return ""

        byte_key = self.validate_key(key)
        
        try:
            ciphertext_bytes = base64.b64decode(ciphertext.encode("utf-8"))
        except (binascii.Error, ValueError) as e:
            raise ValueError("Corrupted ciphertext: invalid Base64 payload.") from e
            
        state_array = self._ksa(byte_key)
        keystream = self._prga(state_array)
        
        plaintext_bytes = bytearray()
        for char_byte in ciphertext_bytes:
            plaintext_bytes.append(char_byte ^ next(keystream))
            
        return plaintext_bytes.decode("utf-8", errors="replace")
