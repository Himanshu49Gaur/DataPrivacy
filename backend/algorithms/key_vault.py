import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt


class KeyVault:
    """
    Secure implementation of a Key Vault for persistent secret management.

    This module provides encrypted storage for cryptographic keys, utilizing
    Scrypt for key derivation and AES-256-GCM for vault-level encryption.
    """

    SALT_LEN = 16
    NONCE_LEN = 16
    TAG_LEN = 16

    def __init__(self, vault_path: str = "vault.json", master_password: str = "default_pwd") -> None:
        """
        Initialize the Key Vault.

        Args:
            vault_path: Path to the vault JSON file.
            master_password: The master password to unlock the vault.
        """
        self.vault_path = vault_path
        self.master_password = master_password
        self._vault_key = None
        self._salt = None

        if os.path.exists(vault_path):
            self._load_metadata()
        else:
            self._salt = os.urandom(self.SALT_LEN)
        
        self._derive_vault_key()

    def _load_metadata(self) -> None:
        """Load salt from existing vault file."""
        with open(self.vault_path, "r") as f:
            data = json.load(f)
            self._salt = base64.b64decode(data["salt"])

    def _derive_vault_key(self) -> None:
        """Derive the 32-byte AES-256 key from the master password."""
        self._vault_key = scrypt(
            self.master_password.encode("utf-8"),
            self._salt,
            32,
            N=16384,
            r=8,
            p=1
        )

    def _read_vault(self) -> dict:
        """Read and return the raw vault data."""
        if not os.path.exists(self.vault_path):
            return {"salt": base64.b64encode(self._salt).decode("utf-8"), "keys": {}}
        with open(self.vault_path, "r") as f:
            return json.load(f)

    def _write_vault(self, data: dict) -> None:
        """Write the vault data to disk."""
        with open(self.vault_path, "w") as f:
            json.dump(data, f, indent=4)

    def save_key(self, name: str, key_data: str) -> None:
        """
        Encrypt and save a key to the vault.

        Args:
            name: The unique identifier for the key.
            key_data: The raw key string to store.
        """
        vault_data = self._read_vault()
        
        cipher = AES.new(self._vault_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(key_data.encode("utf-8"))
        
        vault_data["keys"][name] = {
            "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }
        
        self._write_vault(vault_data)

    def get_key(self, name: str) -> str:
        """
        Retrieve and decrypt a key from the vault.

        Args:
            name: The identifier of the key to retrieve.

        Returns:
            The decrypted key string.

        Raises:
            KeyError: If the key name is not found.
            ValueError: If decryption fails (invalid master password or corruption).
        """
        vault_data = self._read_vault()
        if name not in vault_data["keys"]:
            raise KeyError(f"Key '{name}' not found in vault")
        
        key_entry = vault_data["keys"][name]
        nonce = base64.b64decode(key_entry["nonce"])
        tag = base64.b64decode(key_entry["tag"])
        ciphertext = base64.b64decode(key_entry["ciphertext"])
        
        cipher = AES.new(self._vault_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode("utf-8")
        except ValueError:
            raise ValueError("Failed to decrypt key. Incorrect master password or corrupted vault.")

    def list_keys(self) -> list[str]:
        """
        List all key names stored in the vault.

        Returns:
            A list of key identifiers.
        """
        vault_data = self._read_vault()
        return list(vault_data["keys"].keys())

    def delete_key(self, name: str) -> None:
        """
        Remove a key from the vault.

        Args:
            name: The identifier of the key to delete.
        """
        vault_data = self._read_vault()
        if name in vault_data["keys"]:
            del vault_data["keys"][name]
            self._write_vault(vault_data)
