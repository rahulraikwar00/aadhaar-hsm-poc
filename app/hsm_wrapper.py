# Create the hsm_wrapper.py file

import pkcs11
from pkcs11 import KeyType, Mechanism
import logging
import hashlib
import os
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HSMEncryption:
    """HSM-based encryption helper"""

    def __init__(self, session):
        self.session = session
        self._aes_key = None

    def get_or_create_aes_key(self, label: str = "vault_key", extractable: bool = False) -> Optional[object]:
        """Get or create AES key for vault encryption"""
        if self._aes_key:
            return self._aes_key

        try:
            # Try to find existing key
            for key in self.session.get_objects():
                if hasattr(key, 'label') and key.label == label:
                    self._aes_key = key
                    logger.info(f"Found existing AES key: {label}")
                    return key

            # Generate new AES key for SoftHSM compatibility
            key = self.session.generate_key(
                pkcs11.KeyType.AES,
                length=256,
                label=label,
                token=True,
                private=True,
                sensitive=True,
                extractable=extractable,
                encrypt=True,
                decrypt=True,
                wrap=False,
                unwrap=False
            )
            self._aes_key = key
            logger.info(f"Generated new AES key: {label} (extractable={extractable})")
            return key

        except Exception as e:
            logger.error(f"Failed to get/create AES key: {e}")
            # Fallback: try with extractable=True for SoftHSM
            if not extractable:
                logger.info("Retrying with extractable=True...")
                return self.get_or_create_aes_key(label, extractable=True)
            return None

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES key - fail-closed (raises on failure)"""
        if not self.session:
            raise RuntimeError("HSM session not available - fail-closed: refusing to store plaintext")

        try:
            key = self.get_or_create_aes_key()
            if not key:
                raise RuntimeError("HSM AES key unavailable - fail-closed: refusing to store plaintext")

            iv = os.urandom(12)
            mechanism = Mechanism.AES_GCM(iv)
            encrypted = key.encrypt(data, mechanism=mechanism)

            result = iv + encrypted
            logger.info(f"HSM encrypted {len(data)} bytes -> {len(result)} bytes")
            return result

        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"HSM encryption failed: {e}")
            raise RuntimeError(f"HSM encryption failed: {e}")

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES key - fail-closed (raises on failure)"""
        if not self.session:
            raise RuntimeError("HSM session not available - fail-closed: refusing to decrypt")

        if len(encrypted_data) <= 16:
            raise ValueError("Invalid encrypted data: too short for AES-GCM")

        try:
            key = self.get_or_create_aes_key()
            if not key:
                raise RuntimeError("HSM AES key unavailable - fail-closed: refusing to decrypt")

            iv = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            mechanism = Mechanism.AES_GCM(iv)
            decrypted = key.decrypt(ciphertext, mechanism=mechanism)

            logger.info(f"HSM decrypted {len(encrypted_data)} bytes")
            return decrypted

        except (RuntimeError, ValueError):
            raise
        except Exception as e:
            logger.error(f"HSM decryption failed: {e}")
            raise RuntimeError(f"HSM decryption failed: {e}")

    def _mock_encrypt(self, data: bytes) -> bytes:
        """Mock encryption (for testing without HSM)"""
        key = hashlib.sha256(b"vault_default_key").digest()
        return key[:16] + data + key[:16]

    def _mock_decrypt(self, encrypted_data: bytes) -> bytes:
        """Mock decryption (for testing without HSM)"""
        if len(encrypted_data) > 32:
            return encrypted_data[16:-16]
        return encrypted_data


class HSMWrapper:
    def __init__(self, library_path: str, token_label: str, user_pin: str):
        """Initialize HSM connection"""
        try:
            self.lib = pkcs11.lib(library_path)
            self.token = self.lib.get_token(token_label=token_label)
            self.session = self.token.open(user_pin=user_pin)
            logger.info(f"Connected to HSM token: {token_label}")
        except Exception as e:
            logger.warning(f"HSM not available: {e}")
            self.session = None

    def generate_rsa_key_pair(self, key_label: str, key_size: int = 2048):
        """Generate RSA key pair inside HSM"""
        if not self.session:
            logger.warning("HSM not available, using mock mode")
            return None

        try:
            private_key = self.session.generate_keypair(
                key_type=KeyType.RSA,
                size=key_size,
                label=key_label,
                store=True,
                private=True,
                sensitive=True,
                extractable=False
            )[0]
            logger.info(f"Generated RSA key pair: {key_label}")
            return private_key
        except Exception as e:
            logger.error(f"Failed to generate RSA key: {e}")
            return None

    def sign_data(self, private_key, data: bytes):
        """Sign data using HSM private key"""
        if not self.session or not private_key:
            # Mock signing
            import hashlib
            logger.warning("Using mock signing")
            return hashlib.sha256(data).digest()

        try:
            mechanism = Mechanism.RSA_PKCS
            signature = private_key.sign(data, mechanism=mechanism)
            logger.info(f"Signed {len(data)} bytes")
            return signature
        except Exception as e:
            logger.error(f"Failed to sign data: {e}")
            raise

    def list_keys(self):
        """List all keys in HSM"""
        if not self.session:
            return [{"label": "mock_key", "key_type": "RSA-2048", "status": "mock"}]

        keys = []
        try:
            for key in self.session.get_objects():
                if hasattr(key, 'label') and key.label:
                    keys.append({
                        "label": key.label,
                        "key_type": str(key.key_type),
                        "id": hex(key.id)[:10] if key.id else None
                    })
            return keys
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
            return []

    def close(self):
        """Close HSM session"""
        if self.session:
            try:
                self.session.close()
                logger.info("HSM session closed")
            except:
                pass
