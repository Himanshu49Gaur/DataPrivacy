import string

class Plugboard:
    """
    Simulates the Enigma Plugboard (Steckerbrett).

    The plugboard allows for reciprocal character swaps before and after
    the rotor stack processing.
    """

    def __init__(self, pairs: list[str]) -> None:
        """
        Initializes the Plugboard with character pairs.

        Args:
            pairs (list[str]): A list of strings, each containing two characters
                to be swapped (e.g., ["AB", "CD"]).

        Raises:
            ValueError: If a character is mapped to more than one letter or
                if a pair is invalid.
        """
        self.mapping = list(range(26))
        used_chars = set()

        for pair in pairs:
            if len(pair) != 2:
                raise ValueError(f"Invalid plugboard pair: {pair}")
            
            char1, char2 = pair.upper()
            if char1 == char2:
                raise ValueError(f"Plugboard pair cannot swap a letter with itself: {pair}")
            if not (char1.isalpha() and char2.isalpha()):
                raise ValueError(f"Plugboard pairs must be alphabetic: {pair}")
            
            if char1 in used_chars or char2 in used_chars:
                raise ValueError(f"Duplicate character in plugboard: {char1} or {char2}")
            
            idx1, idx2 = ord(char1) - ord('A'), ord(char2) - ord('A')
            self.mapping[idx1] = idx2
            self.mapping[idx2] = idx1
            used_chars.add(char1)
            used_chars.add(char2)

    def swap(self, char_idx: int) -> int:
        """
        Swaps a character index according to plugboard settings.

        Args:
            char_idx (int): The index of the character (0-25).

        Returns:
            int: The swapped character index.
        """
        return self.mapping[char_idx]


class Rotor:
    """
    Simulates an Enigma Rotor (Walze).
    """

    def __init__(self, wiring: str, notch: str, ring_setting: int, initial_position: int) -> None:
        """
        Initializes the Rotor.

        Args:
            wiring (str): A 26-character string representing the internal wiring.
            notch (str): The turnover notch character.
            ring_setting (int): The Ringstellung (0-25).
            initial_position (int): The Grundstellung (0-25).
        """
        self.forward_wiring = [ord(c) - ord('A') for c in wiring]
        self.backward_wiring = [0] * 26
        for i, val in enumerate(self.forward_wiring):
            self.backward_wiring[val] = i
            
        self.notch_idx = ord(notch.upper()) - ord('A')
        self.ring_setting = ring_setting
        self.position = initial_position

    def is_at_notch(self) -> bool:
        """
        Checks if the rotor is currently at its turnover notch.

        Returns:
            bool: True if at notch, False otherwise.
        """
        return self.position == self.notch_idx

    def step(self) -> None:
        """
        Advances the rotor by one position.
        """
        self.position = (self.position + 1) % 26

    def forward(self, char_idx: int) -> int:
        """
        Passes a signal forward through the rotor.

        Args:
            char_idx (int): Input character index.

        Returns:
            int: Output character index.
        """
        offset = (self.position - self.ring_setting) % 26
        internal_idx = (char_idx + offset) % 26
        output_idx = (self.forward_wiring[internal_idx] - offset) % 26
        return output_idx

    def backward(self, char_idx: int) -> int:
        """
        Passes a signal backward through the rotor.

        Args:
            char_idx (int): Input character index.

        Returns:
            int: Output character index.
        """
        offset = (self.position - self.ring_setting) % 26
        internal_idx = (char_idx + offset) % 26
        output_idx = (self.backward_wiring[internal_idx] - offset) % 26
        return output_idx


class Reflector:
    """
    Simulates the Enigma Reflector (Umkehrwalze).
    """

    def __init__(self, wiring: str) -> None:
        """
        Initializes the Reflector.

        Args:
            wiring (str): A 26-character string representing the wiring.
        """
        self.wiring = [ord(c) - ord('A') for c in wiring]

    def reflect(self, char_idx: int) -> int:
        """
        Reflects the signal back through the rotors.

        Args:
            char_idx (int): Input character index.

        Returns:
            int: Reflected character index.
        """
        return self.wiring[char_idx]


class EnigmaCipher:
    """
    Orchestrates the Enigma M3 Machine simulation.
    """

    HISTORICAL_WIRINGS = {
        'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
        'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
        'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
        'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
        'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z')
    }

    HISTORICAL_REFLECTORS = {
        'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL'
    }

    def __init__(
        self,
        rotors: list[str] = None,
        reflector: str = 'B',
        ring_settings: list[int] = None,
        initial_positions: list[int] = None,
        plugboard_pairs: list[str] = None
    ) -> None:
        """
        Initializes the Enigma machine with specified configuration.

        Args:
            rotors (list[str]): List of 3 rotor names (e.g., ['I', 'II', 'III']).
            reflector (str): Reflector name (e.g., 'B').
            ring_settings (list[int]): List of 3 ring settings (0-25).
            initial_positions (list[int]): List of 3 initial positions (0-25).
            plugboard_pairs (list[str]): List of plugboard pairs (e.g., ['AB', 'CD']).
        """
        if rotors is None:
            rotors = ['I', 'II', 'III']
        if ring_settings is None:
            ring_settings = [0, 0, 0]
        if initial_positions is None:
            initial_positions = [0, 0, 0]
        if plugboard_pairs is None:
            plugboard_pairs = []

        self.validate_configuration(
            rotors, reflector, ring_settings, initial_positions, plugboard_pairs
        )

        self.plugboard = Plugboard(plugboard_pairs)
        self.reflector = Reflector(self.HISTORICAL_REFLECTORS[reflector])
        
        # Enigma M3 has 3 rotors. Order in list: [Left, Middle, Right]
        self.rotor_stack = []
        for i in range(3):
            name = rotors[i]
            wiring, notch = self.HISTORICAL_WIRINGS[name]
            self.rotor_stack.append(
                Rotor(wiring, notch, ring_settings[i], initial_positions[i])
            )

    @classmethod
    def validate_configuration(
        cls,
        rotors: list[str],
        reflector: str,
        ring_settings: list[int],
        initial_positions: list[int],
        plugboard_pairs: list[str]
    ) -> None:
        """
        Validates the Enigma configuration.

        Args:
            rotors (list[str]): Rotor selection.
            reflector (str): Reflector selection.
            ring_settings (list[int]): Ring settings.
            initial_positions (list[int]): Initial positions.
            plugboard_pairs (list[str]): Plugboard pairs.

        Raises:
            ValueError: If configuration is invalid.
        """
        if len(rotors) != 3:
            raise ValueError("Enigma M3 requires exactly 3 rotors.")
        
        for r in rotors:
            if r not in cls.HISTORICAL_WIRINGS:
                raise ValueError(f"Invalid rotor: {r}")
        
        if reflector not in cls.HISTORICAL_REFLECTORS:
            raise ValueError(f"Invalid reflector: {reflector}")
        
        if len(ring_settings) != 3 or len(initial_positions) != 3:
            raise ValueError("Exactly 3 ring settings and initial positions are required.")

    def _step_rotors(self) -> None:
        """
        Handles the electromechanical stepping of rotors, including double-stepping.
        """
        r_left, r_mid, r_right = self.rotor_stack
        
        # Determine which rotors will step
        step_mid = r_right.is_at_notch() or r_mid.is_at_notch()
        step_left = r_mid.is_at_notch()
        
        # Right rotor always steps
        r_right.step()
        
        if step_mid:
            r_mid.step()
        if step_left:
            r_left.step()

    def _process_char(self, char: str) -> str:
        """
        Processes a single character through the machine.

        Args:
            char (str): A single uppercase alphabetic character.

        Returns:
            str: The processed character.
        """
        char_idx = ord(char) - ord('A')
        
        # 1. Rotor stepping
        self._step_rotors()
        
        # 2. Plugboard forward
        char_idx = self.plugboard.swap(char_idx)
        
        # 3. Rotors forward (Right to Left)
        for rotor in reversed(self.rotor_stack):
            char_idx = rotor.forward(char_idx)
            
        # 4. Reflector
        char_idx = self.reflector.reflect(char_idx)
        
        # 5. Rotors backward (Left to Right)
        for rotor in self.rotor_stack:
            char_idx = rotor.backward(char_idx)
            
        # 6. Plugboard backward
        char_idx = self.plugboard.swap(char_idx)
        
        return chr(char_idx + ord('A'))

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext using the Enigma machine.

        Only alphabetic characters are processed (converted to uppercase).
        Non-alphabetic characters are stripped.

        Args:
            plaintext (str): The text to be encrypted.

        Returns:
            str: The encrypted ciphertext.
        """
        sanitized_text = "".join(c.upper() for c in plaintext if c.isalpha())
        result = [self._process_char(c) for c in sanitized_text]
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts ciphertext using the Enigma machine.

        Args:
            ciphertext (str): The text to be decrypted.

        Returns:
            str: The decrypted plaintext.
        """
        return self.encrypt(ciphertext)
