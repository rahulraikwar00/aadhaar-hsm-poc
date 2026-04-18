import uuid
import hashlib
import json
import logging
from typing import Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    DB_AVAILABLE = True
except ImportError:
    logger.warning("psycopg2 not available, using in-memory vault")
    DB_AVAILABLE = False


class AadhaarData:
    def __init__(
        self,
        aadhaar_number: str,
        name: Optional[str] = None,
        date_of_birth: Optional[str] = None,
        gender: Optional[str] = None,
        address: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        biometric_data: Optional[str] = None
    ):
        self.aadhaar_number = aadhaar_number
        self.name = name
        self.date_of_birth = date_of_birth
        self.gender = gender
        self.address = address
        self.phone = phone
        self.email = email
        self.biometric_data = biometric_data

    def to_dict(self) -> dict:
        result = {}
        for attr in ['aadhaar_number', 'name', 'date_of_birth', 'gender', 'address', 'phone', 'email', 'biometric_data']:
            result[attr] = getattr(self, attr, None)
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "AadhaarData":
        return cls(
            aadhaar_number=data.get('aadhaar_number', ''),
            name=data.get('name'),
            date_of_birth=data.get('date_of_birth'),
            gender=data.get('gender'),
            address=data.get('address'),
            phone=data.get('phone'),
            email=data.get('email'),
            biometric_data=data.get('biometric_data')
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "AadhaarData":
        return cls(**{k: v for k, v in data.items() if v is not None})


class TokenResponse:
    def __init__(self, token: str, masked_aadhaar: str, created_at: str):
        self.token = token
        self.masked_aadhaar = masked_aadhaar
        self.created_at = created_at


class DatabaseVault:
    """PostgreSQL-backed vault storage"""

    def __init__(self, db_host: str, db_name: str, db_user: str, db_password: str):
        self.db_host = db_host
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.conn = None
        self._connect()

    def _connect(self):
        """Connect to PostgreSQL"""
        try:
            self.conn = psycopg2.connect(
                host=self.db_host,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            logger.info("Connected to PostgreSQL vault")
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            self.conn = None

    def _mask_aadhaar(self, aadhaar_number: str) -> str:
        """Mask Aadhaar number - show only last 4 digits"""
        if len(aadhaar_number) >= 4:
            return "x" * (len(aadhaar_number) - 4) + aadhaar_number[-4:]
        return "x" * len(aadhaar_number)

    def _mask_data(self, data: dict) -> dict:
        """Mask sensitive fields"""
        masked = {}
        for key, value in data.items():
            if value is None:
                masked[key] = None
            elif key == "aadhaar_number":
                masked[key] = self._mask_aadhaar(value)
            elif key == "email" and value:
                local, domain = value.split("@", 1) if "@" in value else (value, "")
                if len(local) > 2:
                    masked[key] = local[0] + "x" * (len(local) - 2) + local[-1] + "@" + domain
                else:
                    masked[key] = "x" * len(local) + "@" + domain
            elif key == "phone" and value:
                if len(value) >= 4:
                    masked[key] = "x" * (len(value) - 4) + value[-4:]
                else:
                    masked[key] = "x" * len(value)
            else:
                masked[key] = value
        return masked

    def store_data(self, aadhaar_data: AadhaarData, user_id: str = "system") -> TokenResponse:
        """Store Aadhaar data and generate token"""
        if not self.conn:
            raise Exception("Database not connected")

        token = f"T-{uuid.uuid4()}"
        aadhaar_hash = hashlib.sha256(aadhaar_data.aadhaar_number.encode()).hexdigest()
        masked = self._mask_data(aadhaar_data.to_dict())
        created_at = datetime.now().isoformat()

        data_bytes = aadhaar_data.to_json().encode('utf-8')

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO vault_records 
                       (token, encrypted_data, aadhaar_hash, masked_data, created_at, created_by)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (token, data_bytes, aadhaar_hash, json.dumps(masked), created_at, user_id)
                )
                self.conn.commit()

            logger.info(f"Stored data with token: {token}")
            return TokenResponse(
                token=token,
                masked_aadhaar=masked["aadhaar_number"],
                created_at=created_at
            )
        except Exception as e:
            logger.error(f"Failed to store data: {e}")
            self.conn.rollback()
            raise

    def retrieve_data(self, token: str) -> Optional[AadhaarData]:
        """Retrieve data by token"""
        if not self.conn:
            raise Exception("Database not connected")

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT encrypted_data, is_deleted FROM vault_records 
                       WHERE token = %s""",
                    (token,)
                )
                row = cur.fetchone()

            if not row:
                logger.warning(f"Token not found: {token}")
                return None

            encrypted_data, is_deleted = row

            if is_deleted:
                logger.warning(f"Token deleted: {token}")
                return None

            # Handle bytes or memoryview
            if isinstance(encrypted_data, memoryview):
                data_bytes = bytes(encrypted_data)
            elif isinstance(encrypted_data, bytes):
                data_bytes = encrypted_data
            else:
                data_bytes = encrypted_data

            data_str = data_bytes.decode('utf-8')
            data_dict = json.loads(data_str)
            return AadhaarData.from_dict(data_dict)

        except Exception as e:
            logger.error(f"Failed to retrieve data: {e}")
            return None

    def get_masked(self, token: str) -> Optional[dict]:
        """Get masked data only"""
        if not self.conn:
            raise Exception("Database not connected")

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT masked_data, is_deleted FROM vault_records 
                       WHERE token = %s""",
                    (token,)
                )
                row = cur.fetchone()

            if not row:
                return None

            masked_data, is_deleted = row

            if is_deleted:
                return None

            return json.loads(masked_data) if isinstance(masked_data, str) else masked_data

        except Exception as e:
            logger.error(f"Failed to get masked data: {e}")
            return None

    def delete_data(self, token: str) -> bool:
        """Secure delete - mark as deleted without removing"""
        if not self.conn:
            raise Exception("Database not connected")

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """UPDATE vault_records 
                       SET is_deleted = TRUE, deleted_at = %s 
                       WHERE token = %s AND is_deleted = FALSE""",
                    (datetime.now().isoformat(), token)
                )
                self.conn.commit()

            logger.info(f"Deleted token: {token}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete data: {e}")
            self.conn.rollback()
            return False

    def check_duplicate(self, aadhaar_number: str) -> bool:
        """Check if Aadhaar already exists"""
        if not self.conn:
            raise Exception("Database not connected")

        aadhaar_hash = hashlib.sha256(aadhaar_number.encode()).hexdigest()

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT token FROM vault_records 
                       WHERE aadhaar_hash = %s AND is_deleted = FALSE""",
                    (aadhaar_hash,)
                )
                return cur.fetchone() is not None

        except Exception as e:
            logger.error(f"Failed to check duplicate: {e}")
            return False

    def get_token_by_aadhaar(self, aadhaar_number: str) -> Optional[str]:
        """Get token by Aadhaar number"""
        if not self.conn:
            raise Exception("Database not connected")

        aadhaar_hash = hashlib.sha256(aadhaar_number.encode()).hexdigest()

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT token FROM vault_records 
                       WHERE aadhaar_hash = %s AND is_deleted = FALSE""",
                    (aadhaar_hash,)
                )
                row = cur.fetchone()
                return row[0] if row else None

        except Exception as e:
            logger.error(f"Failed to get token by aadhaar: {e}")
            return None

    def check_duplicate_by_token(self, token: str) -> bool:
        """Check if token exists and not deleted"""
        if not self.conn:
            raise Exception("Database not connected")

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT is_deleted FROM vault_records WHERE token = %s""",
                    (token,)
                )
                row = cur.fetchone()
                return row and not row[0]

        except Exception as e:
            logger.error(f"Failed to check token: {e}")
            return False

    def get_all_tokens(self) -> List[str]:
        """List all valid tokens"""
        if not self.conn:
            raise Exception("Database not connected")

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT token FROM vault_records WHERE is_deleted = FALSE"""
                )
                return [row[0] for row in cur.fetchall()]

        except Exception as e:
            logger.error(f"Failed to get all tokens: {e}")
            return []

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


def create_vault(db_host: str, db_name: str, db_user: str, db_password: str) -> DatabaseVault:
    """Factory function to create vault"""
    if DB_AVAILABLE:
        return DatabaseVault(db_host, db_name, db_user, db_password)
    raise Exception("psycopg2 not available")