import string
import random

class MonoalphabeticCipher:
    """
    A class to perform Monoalphabetic Substitution Cipher operations.

    This class provides methods to generate a substitution key, validate it,
    encrypt plaintext, and decrypt ciphertext while preserving character case
    and non-alphabetic characters.
    """

    @classmethod
    def generate_key(cls) -> str:
        """
        Generates a cryptographically safe, randomly shuffled 26-character uppercase string.

        Returns:
            str: A 26-character uppercase string representing the substitution alphabet.
        """
        alphabet = list(string.ascii_uppercase)
        random.SystemRandom().shuffle(alphabet)
        return "".join(alphabet)

    @classmethod
    def validate_key(cls, key: str) -> None:
        """
        Validates the provided substitution key.

        Args:
            key (str): A 26-character substitution key.

        Raises:
            ValueError: If the key is not exactly 26 characters long, contains
                non-alphabetic characters, or contains duplicate characters.
        """
        if len(key) != 26:
            raise ValueError("Key must be exactly 26 characters long.")
        if not key.isalpha():
            raise ValueError("Key must contain only alphabetic characters.")
        if len(set(key.upper())) != 26:
            raise ValueError("Key must contain 26 unique characters.")

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts a plaintext string using a monoalphabetic substitution key.

        Args:
            plaintext (str): The text to be encrypted.
            key (str): A 26-character substitution key.

        Returns:
            str: The encrypted ciphertext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not plaintext:
            return ""

        self.validate_key(key)
        key_upper = key.upper()
        alphabet_upper = string.ascii_uppercase
        
        # Create mapping for both uppercase and lowercase
        mapping = str.maketrans(
            alphabet_upper + alphabet_upper.lower(),
            key_upper + key_upper.lower()
        )
        
        return plaintext.translate(mapping)

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts a ciphertext string using a monoalphabetic substitution key.

        Args:
            ciphertext (str): The text to be decrypted.
            key (str): A 26-character substitution key.

        Returns:
            str: The decrypted plaintext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not ciphertext:
            return ""

        self.validate_key(key)
        key_upper = key.upper()
        alphabet_upper = string.ascii_uppercase
        
        # Create reverse mapping for both uppercase and lowercase
        mapping = str.maketrans(
            key_upper + key_upper.lower(),
            alphabet_upper + alphabet_upper.lower()
        )
        
        return ciphertext.translate(mapping)
