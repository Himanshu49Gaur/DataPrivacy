import math

class TranspositionCipher:
    """
    A class to perform Columnar Transposition Cipher operations.

    This class provides methods to validate a key, encrypt plaintext, and
    decrypt ciphertext using a columnar transposition algorithm that supports
    irregular grids.
    """

    @classmethod
    def validate_key(cls, key: str) -> None:
        """
        Validates the provided transposition key.

        Args:
            key (str): The key string to validate.

        Raises:
            ValueError: If the key is empty, contains non-alphabetic characters,
                or contains duplicate characters.
        """
        if not key:
            raise ValueError("Key cannot be empty.")
        if not key.isalpha():
            raise ValueError("Key must contain only alphabetic characters.")
        if len(set(key.upper())) != len(key):
            raise ValueError("Key must contain unique characters.")

    @classmethod
    def _get_column_order(cls, key: str) -> list[int]:
        """
        Determines the alphabetical order of the characters in the key.

        Args:
            key (str): The validated key string.

        Returns:
            list[int]: A list of integers representing the column processing order.
        """
        key_upper = key.upper()
        # Sort characters with their original indices
        sorted_key = sorted(range(len(key_upper)), key=lambda k: key_upper[k])
        return sorted_key

    def encrypt(self, plaintext: str, key: str) -> str:
        """
        Encrypts plaintext using columnar transposition.

        Args:
            plaintext (str): The text to be encrypted.
            key (str): The transposition key.

        Returns:
            str: The encrypted ciphertext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not plaintext:
            return ""

        self.validate_key(key)
        
        num_columns = len(key)
        col_order = self._get_column_order(key)
        
        # Build columns
        columns = [[] for _ in range(num_columns)]
        for index, char in enumerate(plaintext):
            columns[index % num_columns].append(char)
            
        # Read columns in alphabetical order of key
        ciphertext_parts = []
        for col_idx in col_order:
            ciphertext_parts.append("".join(columns[col_idx]))
            
        return "".join(ciphertext_parts)

    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypts ciphertext using columnar transposition.

        Args:
            ciphertext (str): The text to be decrypted.
            key (str): The transposition key.

        Returns:
            str: The decrypted plaintext.

        Raises:
            ValueError: If the key validation fails.
        """
        if not ciphertext:
            return ""

        self.validate_key(key)
        
        text_length = len(ciphertext)
        num_columns = len(key)
        num_rows = math.ceil(text_length / num_columns)
        num_full_cols = text_length % num_columns
        
        # Calculate lengths of each column in the original grid
        col_lengths = [num_rows] * num_columns
        if num_full_cols != 0:
            for i in range(num_full_cols, num_columns):
                col_lengths[i] = num_rows - 1
                
        col_order = self._get_column_order(key)
        
        # Map ciphertext back to columns
        columns = [None] * num_columns
        current_pos = 0
        for col_idx in col_order:
            length = col_lengths[col_idx]
            columns[col_idx] = list(ciphertext[current_pos : current_pos + length])
            current_pos += length
            
        # Read row by row
        plaintext_chars = []
        for r in range(num_rows):
            for c in range(num_columns):
                if r < len(columns[c]):
                    plaintext_chars.append(columns[c][r])
                    
        return "".join(plaintext_chars)
