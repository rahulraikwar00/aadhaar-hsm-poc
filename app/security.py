import re
import logging
from typing import Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

AADHAAR_REGEX = re.compile(r'^\d{12}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
PHONE_REGEX = re.compile(r'^\d{10,12}$')


class ValidationError(Exception):
    """Custom validation error"""
    pass


class SecurityValidator:
    """Input validation and sanitization"""

    @staticmethod
    def validate_aadhaar(aadhaar_number: str) -> Tuple[bool, Optional[str]]:
        """Validate Aadhaar number format"""
        if not aadhaar_number:
            return False, "Aadhaar number is required"

        aadhaar_clean = aadhaar_number.replace(" ", "").replace("-", "")

        if not aadhaar_clean.isdigit():
            return False, "Aadhaar must contain only digits"

        if len(aadhaar_clean) != 12:
            return False, "Aadhaar must be exactly 12 digits"

        if not AADHAAR_REGEX.match(aadhaar_clean):
            return False, "Invalid Aadhaar format"

        return True, None

    @staticmethod
    def validate_email(email: str) -> Tuple[bool, Optional[str]]:
        """Validate email format"""
        if not email:
            return True, None

        if not EMAIL_REGEX.match(email):
            return False, "Invalid email format"

        return True, None

    @staticmethod
    def validate_phone(phone: str) -> Tuple[bool, Optional[str]]:
        """Validate phone number"""
        if not phone:
            return True, None

        phone_clean = phone.replace(" ", "").replace("-", "").replace("+91", "")

        if not phone_clean.isdigit():
            return False, "Phone must contain only digits"

        if len(phone_clean) < 10 or len(phone_clean) > 12:
            return False, "Phone must be 10-12 digits"

        return True, None

    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Sanitize string input"""
        if not value:
            return ""

        sanitized = value.strip()[:max_length]

        dangerous_chars = ["<", ">", "&", '"', "'", ";", "--", "/*", "*/"]
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")

        return sanitized

    @staticmethod
    def validate_name(name: str) -> Tuple[bool, Optional[str]]:
        """Validate name field"""
        if not name:
            return True, None

        if len(name) < 2:
            return False, "Name must be at least 2 characters"

        if len(name) > 100:
            return False, "Name must be less than 100 characters"

        if not re.match(r'^[a-zA-Z\s\.\-]+$', name):
            return False, "Name contains invalid characters"

        return True, None


class SensitiveDataFilter:
    """Filter sensitive data from logs and responses"""

    SENSITIVE_FIELDS = [
        "aadhaar_number",
        "biometric_data",
        "password",
        "pin",
        "secret",
        "token"
    ]

    SENSITIVE_PATTERNS = [
        r'\d{12}',
        r'\d{10,}',
    ]

    @staticmethod
    def filter_dict(data: dict) -> dict:
        """Filter sensitive fields from dictionary"""
        filtered = {}
        for key, value in data.items():
            if key.lower() in SensitiveDataFilter.SENSITIVE_FIELDS:
                filtered[key] = "***REDACTED***"
            elif value and isinstance(value, str):
                filtered[key] = SensitiveDataFilter.filter_string(value)
            else:
                filtered[key] = value
        return filtered

    @staticmethod
    def filter_string(text: str) -> str:
        """Filter sensitive patterns from string"""
        if not text:
            return text

        filtered = text
        for pattern in SensitiveDataFilter.SENSITIVE_PATTERNS:
            filtered = re.sub(pattern, "***REDACTED***", filtered)

        return filtered

    @staticmethod
    def should_log(field_name: str) -> bool:
        """Check if field should be logged"""
        return field_name.lower() not in SensitiveDataFilter.SENSITIVE_FIELDS


def safe_log(logger_obj, level: str, message: str, extra_data: dict = None):
    """Safe logging that filters sensitive data"""
    if extra_data:
        safe_data = SensitiveDataFilter.filter_dict(extra_data)
        getattr(logger_obj, level)(f"{message} | {safe_data}")
    else:
        getattr(logger_obj, level)(message)