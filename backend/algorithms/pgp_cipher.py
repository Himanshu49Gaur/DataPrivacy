import zlib
import base64
from typing import Tuple
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes


class PGPCipher:
    """
    A streamlined hybrid-cryptosystem modeled on the OpenPGP standard.

    This implementation utilizes AES-GCM for authenticated symmetric encryption
    and RSA-OAEP for key encapsulation, designed for secure, self-contained
    educational demonstration within the application architecture.
    """

    @classmethod
    def generate_keypair(cls, keysize: int = 2048) -> Tuple[str, str]:
        """
        Generate an RSA keypair and export as ASCII-armored PEM strings.

        Args:
            keysize: The bit length of the RSA key (default 2048).

        Returns:
            A tuple containing (private_key_pem, public_key_pem).
        """
        key = RSA.generate(keysize)
        private_key = key.export_key().decode("utf-8")
        public_key = key.publickey().export_key().decode("utf-8")
        return private_key, public_key

    @classmethod
    def encrypt_message(cls, plaintext: str, public_key_pem: str) -> str:
        """
        Encrypt a message using PGP-style hybrid encryption.

        Args:
            plaintext: The message to encrypt.
            public_key_pem: The recipient's RSA public key in PEM format.

        Returns:
            The ASCII-armored PGP message string.
        """
        recipient_key = RSA.import_key(public_key_pem)

        # 1. Compress data
        compressed_data = zlib.compress(plaintext.encode("utf-8"))

        # 2. Generate session key
        session_key = get_random_bytes(32)

        # 3. Encrypt data with AES-GCM
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_data)
        nonce = cipher_aes.nonce

        # 4. Encapsulate session key with RSA-OAEP
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # 5. Serialize payload: [256 EncKey] + [16 Nonce] + [16 Tag] + [Ciphertext]
        payload = enc_session_key + nonce + tag + ciphertext

        # 6. Base64 encode and wrap in ASCII armor
        b64_payload = base64.b64encode(payload).decode("utf-8")
        pgp_message = (
            "-----BEGIN PGP MESSAGE-----\n\n"
            f"{b64_payload}\n"
            "-----END PGP MESSAGE-----"
        )

        return pgp_message

    @classmethod
    def decrypt_message(cls, pgp_message: str, private_key_pem: str) -> str:
        """
        Decrypt a PGP-style hybrid encrypted message.

        Args:
            pgp_message: The ASCII-armored PGP message.
            private_key_pem: The recipient's RSA private key in PEM format.

        Returns:
            The decrypted UTF-8 plaintext string.
        """
        private_key = RSA.import_key(private_key_pem)

        # 1. Strip armor and decode Base64
        lines = pgp_message.strip().split("\n")
        # Find the start of the Base64 content (skip headers)
        start_index = 0
        for i, line in enumerate(lines):
            if line.startswith("-----BEGIN"):
                start_index = i + 1
                # Standard PGP message has a blank line after the header
                if start_index < len(lines) and not lines[start_index].strip():
                    start_index += 1
                break

        # Filter out footer and any potential empty lines
        payload_lines = [
            line for line in lines[start_index:] if not line.startswith("-----END")
        ]
        b64_payload = "".join(payload_lines).strip()
        payload = base64.b64decode(b64_payload)

        # 2. Slice payload
        enc_session_key = payload[:256]
        nonce = payload[256:272]
        tag = payload[272:288]
        ciphertext = payload[288:]

        # 3. Decrypt session key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # 4. Decrypt data
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        compressed_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # 5. Decompress and decode
        plaintext = zlib.decompress(compressed_data).decode("utf-8")

        return plaintext
