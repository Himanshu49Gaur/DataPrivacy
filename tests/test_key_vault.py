import unittest
import os
from backend.algorithms.key_vault import KeyVault


class TestKeyVault(unittest.TestCase):
    """Test suite for KeyVault implementation."""

    def setUp(self):
        self.vault_path = "test_vault.json"
        self.master_pwd = "MasterPassword123!"
        self.vault = KeyVault(self.vault_path, self.master_pwd)

    def tearDown(self):
        if os.path.exists(self.vault_path):
            os.remove(self.vault_path)

    def test_save_and_get_key(self):
        """Tests saving and retrieving a key."""
        key_name = "AES_KEY"
        key_value = "this_is_a_secret_key"
        
        self.vault.save_key(key_name, key_value)
        retrieved = self.vault.get_key(key_name)
        
        self.assertEqual(key_value, retrieved)

    def test_list_keys(self):
        """Tests listing keys in the vault."""
        self.vault.save_key("K1", "V1")
        self.vault.save_key("K2", "V2")
        
        keys = self.vault.list_algorithms() if hasattr(self.vault, "list_algorithms") else self.vault.list_keys()
        self.assertIn("K1", keys)
        self.assertIn("K2", keys)

    def test_wrong_password_fails(self):
        """Tests that a wrong master password prevents decryption."""
        self.vault.save_key("SECRET", "DATA")
        
        # New vault instance with wrong password
        wrong_vault = KeyVault(self.vault_path, "WrongPassword")
        with self.assertRaises(ValueError):
            wrong_vault.get_key("SECRET")

    def test_persistence(self):
        """Tests that vault data persists across instances."""
        self.vault.save_key("PERSISTENT", "STAY")
        
        # Re-instantiate
        new_vault = KeyVault(self.vault_path, self.master_pwd)
        self.assertEqual(new_vault.get_key("PERSISTENT"), "STAY")

    def test_delete_key(self):
        """Tests key deletion."""
        self.vault.save_key("TEMP", "BYE")
        self.vault.delete_key("TEMP")
        
        with self.assertRaises(KeyError):
            self.vault.get_key("TEMP")


if __name__ == "__main__":
    unittest.main()
