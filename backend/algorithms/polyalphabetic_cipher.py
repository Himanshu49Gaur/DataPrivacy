class PolyalphabeticCipher:
    """
    A class to perform Polyalphabetic Substitution Cipher (Vigenère Cipher) operations.

    This class provides methods to validate a key, generate a key stream aligned
    with alphabetic characters, and perform encryption and decryption while
    preserving character case and non-alphabetic characters.
    """

    @classmethod
    def validate_key(cls, key: str) -> None:
        """
        Validates the provided polyalphabetic key.

        Args:
            key (str): The key string to validate.

        Raises:
            ValueError: If the key is empty or contains non-alphabetic characters.
        """
        if not key:
            raise ValueError("Key cannot be empty.")
        if not key.isalpha():
            raise ValueError("Key must contain only alphabetic characters.")

    @classmethod
    def _generate_key_stream(cls, text: str, key: str) -> str:
        """
        Generates a key stream matching the length of the text.

        The key index advances only when an alphabetic character is encountered
        in the target text.

        Args:
            text (str): The target text.
            key (str): The validated key string.

        Returns:
            str: A string of the same length as text containing the key characters
                at alphabetic positions and original characters otherwise.
        """
        key_stream = []
        key_index = 0
        key_len = len(key)
        key_upper = key.upper()

        for char in text:
            if char.isalpha():
                key_stream.append(key_upper[key_index % key_len])
                key_index += 1
            else:
                key_stream.append(char)

        return "".join(key_stream)

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts plaintext using a polyalphabetic shift.

        Args:
            plaintext (str): The text to be encrypted.
            key (str): The encryption key.

        Returns:
            str: The encrypted ciphertext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not plaintext:
            return ""

        self.validate_key(key)
        key_stream = self._generate_key_stream(plaintext, key)
        ciphertext = []

        for p_char, k_char in zip(plaintext, key_stream):
            if p_char.isalpha():
                # Calculate shift amount (0-25)
                shift = ord(k_char) - ord('A')
                # Determine base (A or a)
                base = ord('A') if p_char.isupper() else ord('a')
                # Apply shift
                encrypted_char = chr((ord(p_char) - base + shift) % 26 + base)
                ciphertext.append(encrypted_char)
            else:
                ciphertext.append(p_char)

        return "".join(ciphertext)

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts ciphertext using a polyalphabetic shift.

        Args:
            ciphertext (str): The text to be decrypted.
            key (str): The decryption key.

        Returns:
            str: The decrypted plaintext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not ciphertext:
            return ""

        self.validate_key(key)
        key_stream = self._generate_key_stream(ciphertext, key)
        plaintext = []

        for c_char, k_char in zip(ciphertext, key_stream):
            if c_char.isalpha():
                # Calculate shift amount (0-25)
                shift = ord(k_char) - ord('A')
                # Determine base (A or a)
                base = ord('A') if c_char.isupper() else ord('a')
                # Reverse shift
                decrypted_char = chr((ord(c_char) - base - shift + 26) % 26 + base)
                plaintext.append(decrypted_char)
            else:
                plaintext.append(c_char)

        return "".join(plaintext)
