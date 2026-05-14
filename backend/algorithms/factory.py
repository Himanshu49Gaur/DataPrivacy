from typing import Any, Dict, Type

from .aes_cipher import AESCipher
from .blowfish_cipher import BlowfishCipher
from .cellular_automata_cipher import CellularAutomataCipher
from .chacha20_cipher import ChaCha20Cipher
from .des_cipher import DESCipher
from .diffie_hellman import DiffieHellman
from .ecc_cipher import ECCCipher
from .ecdh_cipher import ECDHCipher
from .ecdsa_cipher import ECDSACipher
from .elgamal_cipher import ElGamalCipher
from .enigma_cipher import EnigmaCipher
from .hmac_auth import HMACAuth
from .key_vault import KeyVault
from .lfsr_cipher import LFSRCipher
from .lucifer_cipher import LuciferCipher
from .monoalphabetic_cipher import MonoalphabeticCipher
from .nlfsr_cipher import NLFSRCipher
from .password_hasher import PasswordHasher
from .pgp_cipher import PGPCipher
from .polyalphabetic_cipher import PolyalphabeticCipher
from .rabin_cipher import RabinCipher
from .rc4_cipher import RC4Cipher
from .rsa_cipher import RSACipher
from .salsa20_cipher import Salsa20Cipher
from .seal_cipher import SEALCipher
from .sha3_hasher import SHA3Hasher
from .transposition_cipher import TranspositionCipher


class CipherFactory:
    """
    Factory class for centralizing access to all cryptographic algorithms.
    """

    _REGISTRY: Dict[str, Type[Any]] = {
        "AES": AESCipher,
        "Blowfish": BlowfishCipher,
        "CellularAutomata": CellularAutomataCipher,
        "ChaCha20": ChaCha20Cipher,
        "DES": DESCipher,
        "DiffieHellman": DiffieHellman,
        "ECC": ECCCipher,
        "ECDH": ECDHCipher,
        "ECDSA": ECDSACipher,
        "ElGamal": ElGamalCipher,
        "Enigma": EnigmaCipher,
        "HMAC": HMACAuth,
        "KeyVault": KeyVault,
        "LFSR": LFSRCipher,
        "Lucifer": LuciferCipher,
        "Monoalphabetic": MonoalphabeticCipher,
        "NLFSR": NLFSRCipher,
        "PasswordHasher": PasswordHasher,
        "PGP": PGPCipher,
        "Polyalphabetic": PolyalphabeticCipher,
        "Rabin": RabinCipher,
        "RC4": RC4Cipher,
        "RSA": RSACipher,
        "Salsa20": Salsa20Cipher,
        "SEAL": SEALCipher,
        "SHA3": SHA3Hasher,
        "Transposition": TranspositionCipher,
    }

    @classmethod
    def create(cls, name: str) -> Any:
        """
        Instantiate a cryptographic algorithm by name.

        Args:
            name: The name of the algorithm (e.g., 'AES', 'ChaCha20').

        Returns:
            An instance of the requested algorithm.

        Raises:
            ValueError: If the algorithm name is not recognized.
        """
        cipher_class = cls._REGISTRY.get(name)
        if not cipher_class:
            available = ", ".join(sorted(cls._REGISTRY.keys()))
            raise ValueError(
                f"Algorithm '{name}' not found. Available: {available}"
            )
        return cipher_class()

    @classmethod
    def list_algorithms(cls) -> list[str]:
        """
        List all available cryptographic algorithms.

        Returns:
            A list of algorithm names.
        """
        return sorted(list(cls._REGISTRY.keys()))
