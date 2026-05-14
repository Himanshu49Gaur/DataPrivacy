import unittest
from backend.algorithms.enigma_cipher import EnigmaCipher, Plugboard, Rotor

class TestEnigmaCipher(unittest.TestCase):
    def test_plugboard_basic(self):
        pb = Plugboard(["AB", "CD"])
        self.assertEqual(pb.swap(0), 1)  # A -> B
        self.assertEqual(pb.swap(1), 0)  # B -> A
        self.assertEqual(pb.swap(2), 3)  # C -> D
        self.assertEqual(pb.swap(4), 4)  # E -> E

    def test_plugboard_invalid(self):
        with self.assertRaises(ValueError):
            Plugboard(["ABC"])
        with self.assertRaises(ValueError):
            Plugboard(["AA"])
        with self.assertRaises(ValueError):
            Plugboard(["AB", "AC"])

    def test_rotor_forward_backward(self):
        # Rotor I: EKMFLGDQVZNTOWYHXUSPAIBRCJ
        wiring = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
        rotor = Rotor(wiring, "Q", 0, 0)
        # A(0) -> E(4)
        self.assertEqual(rotor.forward(0), 4)
        # E(4) -> A(0)
        self.assertEqual(rotor.backward(4), 0)

    def test_enigma_historical_vector(self):
        """
        Test against a known Enigma vector.
        Configuration:
        Rotors: I, II, III
        Reflector: B
        Ring Settings: 0, 0, 0 (AAA)
        Initial Positions: 0, 0, 0 (AAA)
        Plugboard: None
        """
        enigma = EnigmaCipher(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 0, 0],
            plugboard_pairs=[]
        )
        # Pressing 'A' multiple times
        # 1st A: BDZGO... -> First A is B
        # Let's verify first few chars
        result = enigma.encrypt("AAAAA")
        # Known sequence for I-II-III B AAA AAA: BDZGO
        self.assertEqual(result, "BDZGO")

    def test_enigma_reciprocity(self):
        config = {
            "rotors": ["I", "II", "III"],
            "reflector": "B",
            "ring_settings": [5, 10, 15],
            "initial_positions": [1, 2, 3],
            "plugboard_pairs": ["AB", "CD", "EF"]
        }
        plaintext = "ENIGMAISCOMPLEX"
        
        e1 = EnigmaCipher(**config)
        ciphertext = e1.encrypt(plaintext)
        
        e2 = EnigmaCipher(**config)
        decrypted = e2.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)

    def test_double_stepping(self):
        """
        Verify the double-stepping anomaly.
        Middle rotor (II) notch is E.
        If we set positions so R2 is at D and R1 is at its notch (V for III),
        next step should move R2 to E.
        Then next step should move R2 to F and R3 (Left) also steps.
        """
        # Rotor III notch is V (21)
        # Rotor II notch is E (4)
        enigma = EnigmaCipher(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 3, 21], # R2 at D(3), R1 at V(21)
            plugboard_pairs=[]
        )
        
        # Step 1: R1 moves V->W, R2 moves D->E
        enigma.encrypt("A")
        self.assertEqual(enigma.rotor_stack[1].position, 4) # R2 at E
        self.assertEqual(enigma.rotor_stack[2].position, 22) # R1 at W
        
        # Step 2: R1 moves W->X. R2 is at notch E, so it steps E->F and R3 steps A->B.
        enigma.encrypt("A")
        self.assertEqual(enigma.rotor_stack[0].position, 1) # R3 at B (Left)
        self.assertEqual(enigma.rotor_stack[1].position, 5) # R2 at F (Middle)
        self.assertEqual(enigma.rotor_stack[2].position, 23) # R1 at X (Right)

if __name__ == "__main__":
    unittest.main()
