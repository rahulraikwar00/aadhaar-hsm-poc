
from datetime import datetime
import json
import logging
from datetime import datetime, timedelta
import hashlib
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KeyRotationManager:
    def __init__(self, hsm_wrapper, rotation_days: int = 90):
        self.hsm = hsm_wrapper
        self.rotation_days = rotation_days
        self.key_metadata_file = "/app/key_metadata.json"

    def load_metadata(self):
        """Load key rotation metadata"""
        try:
            with open(self.key_metadata_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"keys": [], "current_key_label": None, "last_rotation": None}

    def save_metadata(self, metadata):
        """Save key rotation metadata"""
        with open(self.key_metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

    def rotate_key(self):
        """Generate new key pair and rotate"""
        metadata = self.load_metadata()

        # Generate new key with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_key_label = f"auth_key_{timestamp}"

        logger.info(f"Rotating to new key: {new_key_label}")

        # Try to generate key in HSM if available
        if self.hsm and hasattr(self.hsm, 'generate_rsa_key_pair'):
            try:
                new_private_key = self.hsm.generate_rsa_key_pair(new_key_label)
            except:
                new_private_key = None
                logger.warning("HSM not available, using mock rotation")
        else:
            new_private_key = None
            logger.warning("HSM not available, using mock rotation")

        # Update metadata
        new_key_info = {
            "label": new_key_label,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=self.rotation_days)).isoformat(),
            "is_current": True
        }

        # Mark previous current key as retired
        for key in metadata["keys"]:
            key["is_current"] = False

        metadata["keys"].append(new_key_info)
        metadata["current_key_label"] = new_key_label
        metadata["last_rotation"] = datetime.now().isoformat()

        self.save_metadata(metadata)
        logger.info(f"Key rotation complete. New key: {new_key_label}")

        return new_private_key

    def get_current_key(self):
        """Get current active key"""
        metadata = self.load_metadata()
        current_label = metadata.get("current_key_label")

        if not current_label:
            logger.info("No current key found, performing initial rotation")
            return self.rotate_key()

        logger.info(f"Using current key: {current_label}")
        return {"label": current_label, "mock": True}

    def prevent_unauthorized_substitution(self, proposed_key_label):
        """Check if a key is authorized (prevents substitution attacks)"""
        metadata = self.load_metadata()

        # Check if key exists in metadata
        key_exists = any(
            k["label"] == proposed_key_label for k in metadata["keys"])

        if not key_exists:
            logger.error(
                f"UNAUTHORIZED KEY SUBSTITUTION ATTEMPT: {proposed_key_label}")
            return False

        # Check if key is not expired
        for key_info in metadata["keys"]:
            if key_info["label"] == proposed_key_label:
                expires_at = datetime.fromisoformat(key_info["expires_at"])
                if expires_at < datetime.now():
                    logger.error(
                        f"Expired key attempted: {proposed_key_label}")
                    return False

        return True

    def check_rotation_needed(self):
        """Check if rotation is needed based on age"""
        metadata = self.load_metadata()
        if not metadata.get("last_rotation"):
            return True

        last_rotation = datetime.fromisoformat(metadata["last_rotation"])
        days_since_rotation = (datetime.now() - last_rotation).days

        if days_since_rotation >= self.rotation_days:
            logger.info(
                f"Key rotation needed (last rotation {days_since_rotation} days ago)")
            return True

        return False


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseAuditLogger:
    """Audit logger with file fallback"""

    def __init__(self, db_host=None, db_name=None, db_user=None, db_password=None):
        self.db_available = False
        self.file_logger = FileAuditLogger()

        # Try to connect to PostgreSQL if credentials provided
        if db_host and db_user:
            try:
                import psycopg2
                self.conn = psycopg2.connect(
                    host=db_host,
                    database=db_name,
                    user=db_user,
                    password=db_password
                )
                self.db_available = True
                logger.info("PostgreSQL audit logging enabled")
            except Exception as e:
                logger.warning(
                    f"PostgreSQL unavailable, using file-based audit: {e}")
                self.db_available = False

    def log_crypto_operation(self, operation, key_label, user_id, details=""):
        """Log operation to DB or file"""
        if self.db_available:
            return self._log_to_db(operation, key_label, user_id, details)
        else:
            return self._log_to_file(operation, key_label, user_id, details)

    def _log_to_db(self, operation, key_label, user_id, details):
        """Log to PostgreSQL"""
        try:
            cursor = self.conn.cursor()
            previous_hash = self._get_last_hash_db()

            # Create log entry
            entry = {
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "key_label": key_label,
                "user_id": user_id,
                "details": details,
                "previous_hash": previous_hash
            }

            entry_str = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()

            cursor.execute("""
                INSERT INTO audit_logs (timestamp, operation, key_label, user_id, details, previous_hash, hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (datetime.now(), operation, key_label, user_id, details, previous_hash, entry_hash))

            audit_id = cursor.fetchone()[0]
            self.conn.commit()
            cursor.close()

            return audit_id
        except Exception as e:
            logger.error(f"DB audit failed: {e}")
            return self._log_to_file(operation, key_label, user_id, details)

    def _log_to_file(self, operation, key_label, user_id, details):
        """Fallback to file-based logging"""
        return self.file_logger.log_crypto_operation(operation, key_label, user_id, details)

    def _get_last_hash_db(self):
        """Get last hash from DB for chain"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else "0" * 64
        except:
            return "0" * 64

    def get_recent_logs(self, limit=100):
        """Get recent logs"""
        if self.db_available:
            try:
                cursor = self.conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, operation, key_label, user_id, details 
                    FROM audit_logs 
                    ORDER BY id DESC 
                    LIMIT %s
                """, (limit,))
                logs = []
                for row in cursor.fetchall():
                    logs.append({
                        "id": row[0],
                        "timestamp": row[1].isoformat(),
                        "operation": row[2],
                        "key_label": row[3],
                        "user_id": row[4],
                        "details": row[5]
                    })
                cursor.close()
                return logs
            except:
                return self.file_logger.get_recent_logs(limit)
        else:
            return self.file_logger.get_recent_logs(limit)


class FileAuditLogger:
    """File-based fallback audit logger"""

    def __init__(self, log_file="/var/log/aadhaar_hsm/audit.log"):
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def log_crypto_operation(self, operation, key_label, user_id, details=""):
        """Log to file"""
        entry = {
            "id": int(datetime.now().timestamp()),
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "key_label": key_label,
            "user_id": user_id,
            "details": details
        }

        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

        return entry["id"]

    def get_recent_logs(self, limit=100):
        """Read recent logs from file"""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-limit:]:
                    logs.append(json.loads(line))
        except:
            pass
        return logs
