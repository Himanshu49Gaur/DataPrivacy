import argparse
import sys
import base64
from typing import Any

from .algorithms.factory import CipherFactory


def main():
    """
    Main entry point for the Data Privacy Toolkit CLI.
    """
    parser = argparse.ArgumentParser(
        description="Data Privacy Toolkit - A collection of 22 cryptographic algorithms."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: list
    subparsers.add_parser("list", help="List all available algorithms")

    # Command: encrypt
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    encrypt_parser.add_argument("algo", help="Algorithm name (e.g., AES, ChaCha20)")
    encrypt_parser.add_argument("data", help="Plaintext to encrypt")
    encrypt_parser.add_argument("--key", help="Encryption key (string or hex)")
    encrypt_parser.add_argument("--keyfile", help="Path to key file")
    encrypt_parser.add_argument("--nonce", help="Nonce for stream ciphers (hex)")
    encrypt_parser.add_argument(
        "--mode", help="Mode for AES (gcm, cbc)", default="gcm"
    )

    # Command: decrypt
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    decrypt_parser.add_argument("algo", help="Algorithm name")
    decrypt_parser.add_argument("data", help="Base64 encoded ciphertext")
    decrypt_parser.add_argument("--key", help="Decryption key")
    decrypt_parser.add_argument("--keyfile", help="Path to key file")
    decrypt_parser.add_argument("--nonce", help="Nonce (hex)")
    decrypt_parser.add_argument("--mode", help="Mode for AES", default="gcm")

    args = parser.parse_args()

    if args.command == "list":
        algos = CipherFactory.list_algorithms()
        print("Available Algorithms:")
        for algo in algos:
            print(f" - {algo}")
        return

    if args.command in ["encrypt", "decrypt"]:
        try:
            cipher = CipherFactory.create(args.algo)
            
            # Key handling
            key = args.key
            if args.keyfile:
                with open(args.keyfile, "r") as f:
                    key = f.read().strip()
            
            if not key and args.algo not in ["Enigma", "Transposition", "Monoalphabetic", "CellularAutomata"]:
                print("Error: --key or --keyfile is required for this algorithm.")
                sys.exit(1)

            # Execution
            if args.command == "encrypt":
                result = run_encrypt(cipher, args.algo, args.data, key, args)
                print(f"Ciphertext (Base64 or Raw): {result}")
            else:
                result = run_decrypt(cipher, args.algo, args.data, key, args)
                print(f"Plaintext: {result}")

        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    else:
        parser.print_help()


def run_encrypt(cipher: Any, algo: str, data: str, key: str, args: argparse.Namespace) -> str:
    """Helper to route encryption calls based on algorithm signature."""
    if algo == "AES":
        if args.mode.lower() == "gcm":
            return cipher.encrypt_gcm(data, key)
        return cipher.encrypt_cbc(data, key)
    
    if algo in ["ChaCha20", "Salsa20"]:
        nonce = bytes.fromhex(args.nonce) if args.nonce else (b"0" * (12 if algo == "ChaCha20" else 8))
        return cipher.encrypt(data, key.encode("utf-8"), nonce)
    
    if algo == "ECDH":
        # For ECDH in CLI, data is the peer public key as a tuple string "(x,y)"
        peer_pub = eval(data)
        return cipher.compute_shared_secret(int(key), peer_pub)

    if algo in ["RSA", "Rabin", "ElGamal"]:
        # Simple int conversion for basic primitives if key is provided as number
        try:
            pub_key = int(key)
        except ValueError:
            pub_key = key # Handle PEM strings if applicable (like in PGP)
        
        if algo == "PGP":
            return cipher.encrypt_message(data, key)
        return cipher.encrypt(data, pub_key)
    
    # Generic symmetric
    try:
        return cipher.encrypt(data, key)
    except TypeError:
        # Some ciphers might not take a key (e.g., Enigma with internal state)
        return cipher.encrypt(data)


def run_decrypt(cipher: Any, algo: str, data: str, key: str, args: argparse.Namespace) -> str:
    """Helper to route decryption calls based on algorithm signature."""
    if algo == "AES":
        if args.mode.lower() == "gcm":
            return cipher.decrypt_gcm(data, key)
        return cipher.decrypt_cbc(data, key)

    if algo in ["ChaCha20", "Salsa20"]:
        nonce = bytes.fromhex(args.nonce) if args.nonce else (b"0" * (12 if algo == "ChaCha20" else 8))
        return cipher.decrypt(data, key.encode("utf-8"), nonce)

    if algo in ["RSA", "Rabin", "ElGamal"]:
        try:
            priv_key = eval(key) if "(" in key else int(key) # Handle tuples (p,q) or ints
        except Exception:
            priv_key = key
            
        if algo == "PGP":
            return cipher.decrypt_message(data, key)
        return cipher.decrypt(data, priv_key)

    try:
        return cipher.decrypt(data, key)
    except TypeError:
        return cipher.decrypt(data)


if __name__ == "__main__":
    main()
