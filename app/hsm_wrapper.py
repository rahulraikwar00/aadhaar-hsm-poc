# Create the hsm_wrapper.py file

import pkcs11
from pkcs11 import KeyType, Mechanism
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
