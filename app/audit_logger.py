import json
import hashlib
from datetime import datetime
import os
import logging
from typing import Optional, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import psycopg2
    DB_AVAILABLE = True
except ImportError:
    logger.warning("psycopg2 not available")
    DB_AVAILABLE = False


class DatabaseAuditLogger:
    """Audit logger with PostgreSQL backend"""

    def __init__(self, db_host=None, db_name=None, db_user=None, db_password=None):
        self.db_host = db_host or os.getenv('DB_HOST', 'postgres')
        self.db_name = db_name or os.getenv('DB_NAME', 'aadhaar_audit')
        self.db_user = db_user or os.getenv('DB_USER', 'audit_user')
        self.db_password = db_password or os.getenv('DB_PASSWORD', 'AuditPass2025!')
        self.conn = None
        self.db_available = False

        # Try to connect to PostgreSQL
        if DB_AVAILABLE:
            try:
                self.conn = psycopg2.connect(
                    host=self.db_host,
                    database=self.db_name,
                    user=self.db_user,
                    password=self.db_password
                )
                self.db_available = True
                logger.info("Audit logger initialized (PostgreSQL)")
            except Exception as e:
                logger.warning(f"Failed to connect to PostgreSQL: {e}")
                # Fallback to file
                self.file_logger = FileAuditLogger()
                logger.info("Falling back to file-based audit logging")
        else:
            self.file_logger = FileAuditLogger()
            logger.info("Audit logger initialized (file-based mode)")

    def log_crypto_operation(self, operation, key_label, user_id, details="") -> int:
        """Log operation to PostgreSQL or file"""
        if self.db_available and self.conn:
            return self._log_to_db(operation, key_label, user_id, details)
        else:
            return self.file_logger.log_crypto_operation(operation, key_label, user_id, details)

    def _log_to_db(self, operation, key_label, user_id, details="") -> int:
        """Log to PostgreSQL database"""
        try:
            timestamp = datetime.now().isoformat()
            details_json = json.dumps({"details": details}) if details else None

            # Calculate hash for audit chain
            hash_input = f"{timestamp}{operation}{key_label}{user_id}"
            hash_value = hashlib.sha256(hash_input.encode()).hexdigest()

            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO audit_logs 
                       (timestamp, operation, key_label, user_id, details, hash)
                       VALUES (%s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (timestamp, operation, key_label, user_id, details_json, hash_value)
                )
                self.conn.commit()
                result = cur.fetchone()
                logger.info(f"Logged to PostgreSQL: {operation} by {user_id}")
                return result[0] if result else 0

        except Exception as e:
            logger.error(f"Failed to log to database: {e}")
            self.conn.rollback()
            # Fallback to file
            return self.file_logger.log_crypto_operation(operation, key_label, user_id, details)

    def log_vault_operation(self, operation: str, token: str, user_id: str, details: dict = None) -> int:
        """Log vault operation to vault_audit table"""
        if not (self.db_available and self.conn):
            logger.warning("Database not available for vault audit logging")
            return 0

        try:
            timestamp = datetime.now().isoformat()
            details_json = json.dumps(details) if details else None

            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO vault_audit 
                       (token, operation, user_id, timestamp, details)
                       VALUES (%s, %s, %s, %s, %s)
                       RETURNING id""",
                    (token, operation, user_id, timestamp, details_json)
                )
                self.conn.commit()
                result = cur.fetchone()
                logger.info(f"Logged vault operation to PostgreSQL: {operation} for token {token}")
                return result[0] if result else 0

        except Exception as e:
            logger.error(f"Failed to log vault operation: {e}")
            return 0

    def get_recent_logs(self, limit: int = 100) -> List[dict]:
        """Get recent audit logs"""
        if self.db_available and self.conn:
            return self._get_logs_from_db(limit)
        else:
            return self.file_logger.get_recent_logs(limit)

    def _get_logs_from_db(self, limit: int) -> List[dict]:
        """Get logs from PostgreSQL"""
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """SELECT id, timestamp, operation, key_label, user_id, details 
                       FROM audit_logs 
                       ORDER BY id DESC 
                       LIMIT %s""",
                    (limit,)
                )
                rows = cur.fetchall()
                logs = []
                for row in rows:
                    logs.append({
                        "id": row[0],
                        "timestamp": row[1].isoformat() if row[1] else None,
                        "operation": row[2],
                        "key_label": row[3],
                        "user_id": row[4],
                        "details": row[5]
                    })
                return logs
        except Exception as e:
            logger.error(f"Failed to get logs from database: {e}")
            return []

    def get_vault_logs(self, token: str = None, limit: int = 100) -> List[dict]:
        """Get vault audit logs"""
        if not (self.db_available and self.conn):
            return []

        try:
            with self.conn.cursor() as cur:
                if token:
                    cur.execute(
                        """SELECT id, token, operation, user_id, timestamp, details 
                       FROM vault_audit 
                       WHERE token = %s
                       ORDER BY id DESC 
                       LIMIT %s""",
                        (token, limit)
                    )
                else:
                    cur.execute(
                        """SELECT id, token, operation, user_id, timestamp, details 
                       FROM vault_audit 
                       ORDER BY id DESC 
                       LIMIT %s""",
                        (limit,)
                    )
                rows = cur.fetchall()
                logs = []
                for row in rows:
                    logs.append({
                        "id": row[0],
                        "token": row[1],
                        "operation": row[2],
                        "user_id": row[3],
                        "timestamp": row[4].isoformat() if row[4] else None,
                        "details": row[5]
                    })
                return logs
        except Exception as e:
            logger.error(f"Failed to get vault logs: {e}")
            return []

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class FileAuditLogger:
    """File-based audit logger (fallback)"""

    def __init__(self, log_file="/var/log/aadhaar_hsm/audit.log"):
        self.log_file = log_file
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
        except:
            pass

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

        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except:
            pass

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