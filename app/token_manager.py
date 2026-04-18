import uuid
import hashlib
import time
import logging
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class TokenMetadata:
    """Metadata associated with a token"""

    def __init__(
        self,
        token: str,
        aadhaar_hash: str,
        created_at: str,
        created_by: str,
        expires_at: Optional[str] = None,
        is_revoked: bool = False,
        revocation_reason: Optional[str] = None
    ):
        self.token = token
        self.aadhaar_hash = aadhaar_hash
        self.created_at = created_at
        self.created_by = created_by
        self.expires_at = expires_at
        self.is_revoked = is_revoked
        self.revocation_reason = revocation_reason


class TokenManager:
    """Advanced token generation and management"""

    TOKEN_PREFIX = "T"
    TOKEN_VERSION = "1"
    TOKEN_LENGTH = 16

    def __init__(self, token_ttl_days: int = 0):
        self.token_ttl_days = token_ttl_days
        self.token_registry: dict[str, TokenMetadata] = {}
        self.hash_to_token: dict[str, str] = {}
        logger.info(f"TokenManager initialized (TTL: {token_ttl_days} days)")

    def generate_token(
        self,
        aadhaar_number: str,
        user_id: str = "system"
    ) -> tuple[str, str]:
        """Generate token and return (token, aadhaar_hash)"""
        aadhaar_hash = hashlib.sha256(aadhaar_number.encode()).hexdigest()[:16]

        token = self._generate_deterministic_token(aadhaar_hash, user_id)
        aadhaar_hash_full = hashlib.sha256(aadhaar_number.encode()).hexdigest()

        expires_at = None
        if self.token_ttl_days > 0:
            expires = datetime.now() + timedelta(days=self.token_ttl_days)
            expires_at = expires.isoformat()

        metadata = TokenMetadata(
            token=token,
            aadhaar_hash=aadhaar_hash_full,
            created_at=datetime.now().isoformat(),
            created_by=user_id,
            expires_at=expires_at
        )

        self.token_registry[token] = metadata
        self.hash_to_token[aadhaar_hash_full] = token

        logger.info(f"Generated token: {token}")
        return token, aadhaar_hash_full

    def _generate_deterministic_token(
        self,
        aadhaar_hash: str,
        user_id: str
    ) -> str:
        """Generate deterministic token based on hash + timestamp"""
        timestamp = int(time.time())
        combined = f"{self.TOKEN_PREFIX}{aadhaar_hash}{user_id}{timestamp}"
        hash_digest = hashlib.sha256(combined.encode()).hexdigest()[:self.TOKEN_LENGTH]
        return f"{self.TOKEN_PREFIX}-{self.TOKEN_VERSION}-{hash_digest}"

    def _generate_random_token(self) -> str:
        """Generate random unique token"""
        return f"{self.TOKEN_PREFIX}-{uuid.uuid4()}"

    def validate_token_format(self, token: str) -> bool:
        """Validate token format"""
        if not token:
            return False

        parts = token.split("-")
        if len(parts) != 3:
            return False

        prefix, version, payload = parts
        if prefix != self.TOKEN_PREFIX:
            return False

        if version != self.TOKEN_VERSION:
            return False

        if len(payload) != self.TOKEN_LENGTH:
            return False

        return True

    def revoke_token(
        self,
        token: str,
        reason: str = "manual"
    ) -> bool:
        """Revoke a token"""
        if token not in self.token_registry:
            return False

        self.token_registry[token].is_revoked = True
        self.token_registry[token].revocation_reason = reason
        logger.info(f"Revoked token: {token} ({reason})")
        return True

    def is_token_valid(self, token: str) -> bool:
        """Check if token is valid"""
        if token not in self.token_registry:
            return False

        metadata = self.token_registry[token]
        if metadata.is_revoked:
            return False

        if metadata.expires_at:
            expires = datetime.fromisoformat(metadata.expires_at)
            if datetime.now() > expires:
                return False

        return True

    def lookup_by_aadhaar(self, aadhaar_number: str) -> Optional[str]:
        """Look up token by Aadhaar number"""
        aadhaar_hash = hashlib.sha256(aadhaar_number.encode()).hexdigest()
        return self.hash_to_token.get(aadhaar_hash)

    def get_metadata(self, token: str) -> Optional[TokenMetadata]:
        """Get token metadata"""
        return self.token_registry.get(token)

    def list_valid_tokens(self) -> list[str]:
        """List all valid (non-revoked, non-expired) tokens"""
        valid = []
        for token, metadata in self.token_registry.items():
            if not metadata.is_revoked:
                if metadata.expires_at:
                    expires = datetime.fromisoformat(metadata.expires_at)
                    if datetime.now() > expires:
                        continue
                valid.append(token)
        return valid


def mask_aadhaar(aadhaar_number: str, visible_digits: int = 4) -> str:
    """Mask Aadhaar number showing only last N digits"""
    if len(aadhaar_number) <= visible_digits:
        return "x" * len(aadhaar_number)
    return "x" * (len(aadhaar_number) - visible_digits) + aadhaar_number[-visible_digits:]


def mask_email(email: str) -> str:
    """Mask email address"""
    if "@" not in email:
        return "x" * len(email)

    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "x" * len(local)
    else:
        masked_local = local[0] + "x" * (len(local) - 2) + local[-1]

    return f"{masked_local}@{domain}"


def mask_phone(phone: str) -> str:
    """Mask phone number showing only last 4 digits"""
    if len(phone) <= 4:
        return "x" * len(phone)
    return "x" * (len(phone) - 4) + phone[-4:]