import unittest
import subprocess
import sys


class TestToolkitCLI(unittest.TestCase):
    """Test suite for the Data Privacy Toolkit CLI."""

    def run_cli(self, args):
        """Helper to run the CLI as a subprocess."""
        cmd = [sys.executable, "-m", "backend.cli"] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def test_cli_list(self):
        """Tests the 'list' command."""
        result = self.run_cli(["list"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("AES", result.stdout)
        self.assertIn("ChaCha20", result.stdout)

    def test_cli_aes_encrypt_decrypt(self):
        """Tests AES encryption/decryption via CLI."""
        key = "this_is_a_32_byte_key_for_aes256"
        message = "CLI_Test_Message"
        
        # Encrypt
        enc_result = self.run_cli(["encrypt", "AES", message, "--key", key])
        self.assertEqual(enc_result.returncode, 0)
        ciphertext = enc_result.stdout.split(": ")[1].strip()
        
        # Decrypt
        dec_result = self.run_cli(["decrypt", "AES", ciphertext, "--key", key])
        self.assertEqual(dec_result.returncode, 0)
        self.assertIn(message, dec_result.stdout)

    def test_cli_chacha20(self):
        """Tests ChaCha20 via CLI."""
        key = "this_is_a_32_byte_key_for_aes256"
        message = "Stream_CLI_Test"
        
        enc_result = self.run_cli(["encrypt", "ChaCha20", message, "--key", key])
        ciphertext = enc_result.stdout.split(": ")[1].strip()
        
        dec_result = self.run_cli(["decrypt", "ChaCha20", ciphertext, "--key", key])
        self.assertIn(message, dec_result.stdout)

    def test_cli_error_handling(self):
        """Tests that invalid algorithm names result in error."""
        result = self.run_cli(["encrypt", "InvalidAlgo", "data", "--key", "key"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error", result.stdout)


if __name__ == "__main__":
    unittest.main()
