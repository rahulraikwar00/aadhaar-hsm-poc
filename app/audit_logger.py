
import json
import hashlib
from datetime import datetime
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseAuditLogger:
    """Audit logger with file fallback"""

    def __init__(self, db_host=None, db_name=None, db_user=None, db_password=None):
        self.db_available = False
        self.file_logger = FileAuditLogger()
        logger.info("Audit logger initialized (file-based mode)")

    def log_crypto_operation(self, operation, key_label, user_id, details=""):
        """Log operation to file"""
        return self.file_logger.log_crypto_operation(operation, key_label, user_id, details)

    def get_recent_logs(self, limit=100):
        """Get recent logs"""
        return self.file_logger.get_recent_logs(limit)


class FileAuditLogger:
    """File-based audit logger"""

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
