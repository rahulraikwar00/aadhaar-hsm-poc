from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid
import hashlib
import logging

try:
    from token_manager import mask_aadhaar, mask_email, mask_phone
except ImportError:
    def mask_aadhaar(aadhaar_number: str, visible_digits: int = 4) -> str:
        if len(aadhaar_number) <= visible_digits:
            return "x" * len(aadhaar_number)
        return "x" * (len(aadhaar_number) - visible_digits) + aadhaar_number[-visible_digits:]

    def mask_email(email: str) -> str:
        if "@" not in email:
            return "x" * len(email)
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = "x" * len(local)
        else:
            masked_local = local[0] + "x" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"

    def mask_phone(phone: str) -> str:
        if len(phone) <= 4:
            return "x" * len(phone)
        return "x" * (len(phone) - 4) + phone[-4:]

logger = logging.getLogger(__name__)


class AadhaarData(BaseModel):
    aadhaar_number: str
    name: Optional[str] = None
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    biometric_data: Optional[str] = None


class TokenResponse(BaseModel):
    token: str
    masked_aadhaar: str
    created_at: str
    expires_at: Optional[str] = None


class VaultStore(BaseModel):
    token: str
    encrypted_data: str
    masked_data: dict
    created_at: str
    created_by: str
    is_deleted: bool = False


class Vault:
    """In-memory vault storage (for PoC - use PostgreSQL in production)"""

    def __init__(self):
        self.store: dict[str, VaultStore] = {}
        logger.info("Vault initialized")

    def store_data(self, aadhaar_data: AadhaarData, user_id: str = "system") -> TokenResponse:
        """Store Aadhaar data and generate token"""
        token = self._generate_token()
        masked = self._mask_aadhaar(aadhaar_data.aadhaar_number)
        created_at = datetime.now().isoformat()

        raw_data = aadhaar_data.model_dump()
        masked_fields = self._mask_data(raw_data)

        vault_entry = VaultStore(
            token=token,
            encrypted_data=aadhaar_data.model_dump_json(),
            masked_data=masked_fields,
            created_at=created_at,
            created_by=user_id,
            is_deleted=False
        )

        self.store[token] = vault_entry
        logger.info(f"Stored data with token: {token}")

        return TokenResponse(
            token=token,
            masked_aadhaar=masked,
            created_at=created_at
        )

    def retrieve_data(self, token: str) -> Optional[AadhaarData]:
        """Retrieve data by token"""
        if token not in self.store:
            logger.warning(f"Token not found: {token}")
            return None

        entry = self.store[token]
        if entry.is_deleted:
            logger.warning(f"Token deleted: {token}")
            return None

        return AadhaarData.model_validate_json(entry.encrypted_data)

    def get_masked(self, token: str) -> Optional[dict]:
        """Get masked data only"""
        if token not in self.store:
            return None

        entry = self.store[token]
        if entry.is_deleted:
            return None

        return entry.masked_data

    def delete_data(self, token: str) -> bool:
        """Secure delete - mark as deleted without removing"""
        if token not in self.store:
            return False

        self.store[token].is_deleted = True
        logger.info(f"Deleted token: {token}")
        return True

    def check_duplicate(self, aadhaar_number: str) -> bool:
        """Check if Aadhaar already exists"""
        for entry in self.store.values():
            if entry.is_deleted:
                continue
            if aadhaar_number in entry.encrypted_data:
                return True
        return False

    def check_duplicate_by_token(self, token: str) -> bool:
        """Check if token exists and not deleted"""
        if token in self.store:
            return not self.store[token].is_deleted
        return False

    def get_all_tokens(self) -> List[str]:
        """List all valid tokens"""
        return [
            token for token, entry in self.store.items()
            if not entry.is_deleted
        ]

    def _generate_token(self) -> str:
        """Generate unique token (T-UUID format)"""
        return f"T-{uuid.uuid4()}"

    def _mask_aadhaar(self, aadhaar_number: str) -> str:
        """Mask Aadhaar number - show only last 4 digits"""
        return mask_aadhaar(aadhaar_number)

    def _mask_data(self, data: dict) -> dict:
        """Mask various sensitive fields"""
        masked = {}
        for key, value in data.items():
            if value is None:
                masked[key] = None
            elif key == "aadhaar_number":
                masked[key] = mask_aadhaar(value)
            elif key == "email":
                masked[key] = mask_email(value)
            elif key == "phone":
                masked[key] = mask_phone(value)
            else:
                masked[key] = value
        return masked


vault = Vault()