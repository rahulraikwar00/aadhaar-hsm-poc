from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import json
import hashlib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Aadhaar HSM Gateway", version="1.0.0")

# Try to import modules with fallbacks
HSM_AVAILABLE = False
key_manager = None
audit_logger = None

try:
    from hsm_wrapper import HSMWrapper
    HSM_AVAILABLE = True
    logger.info("HSM wrapper imported")
except ImportError as e:
    logger.warning(f"HSM wrapper not available: {e}")

try:
    from key_rotation_manager import KeyRotationManager
    logger.info("Key rotation manager imported")
except ImportError as e:
    logger.warning(f"Key rotation manager not available: {e}")

try:
    from audit_logger import DatabaseAuditLogger
    logger.info("Audit logger imported")
except ImportError as e:
    logger.warning(f"Audit logger not available: {e}")

# Initialize components
hsm = None
if HSM_AVAILABLE:
    try:
        hsm = HSMWrapper(
            library_path=os.getenv(
                'HSM_LIBRARY', '/usr/lib/softhsm/libsofthsm2.so'),
            token_label=os.getenv('HSM_TOKEN_LABEL', 'AuthToken'),
            user_pin=os.getenv('HSM_USER_PIN', '12345678')
        )
        logger.info("HSM initialized")

        # Initialize key manager if available
        try:
            key_manager = KeyRotationManager(hsm)
            logger.info("Key rotation manager initialized")
        except:
            pass

        # Initialize audit logger
        try:
            audit_logger = DatabaseAuditLogger(
                db_host=os.getenv('DB_HOST'),
                db_name=os.getenv('DB_NAME'),
                db_user=os.getenv('DB_USER'),
                db_password=os.getenv('DB_PASSWORD')
            )
            logger.info("Audit logger initialized")
        except:
            pass

    except Exception as e:
        logger.warning(f"HSM initialization failed: {e}")
        hsm = None


class AuthRequest(BaseModel):
    aadhaar_ref: str
    biometric_data: str
    user_id: str
    purpose: str


class AuthResponse(BaseModel):
    signed_request: str
    signature: str
    key_label: str
    timestamp: str
    mock_mode: bool


@app.get("/")
async def root():
    return {
        "message": "Aadhaar HSM Gateway",
        "status": "running",
        "hsm_available": hsm is not None,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "hsm_available": hsm is not None,
        "timestamp": datetime.now().isoformat()
    }


@app.post("/auth/sign", response_model=AuthResponse)
async def sign_auth_request(request: AuthRequest):
    """Sign authentication request"""

    # Create request payload
    payload = {
        "aadhaar_ref": request.aadhaar_ref,
        "biometric_hash": hashlib.sha256(request.biometric_data.encode()).hexdigest(),
        "purpose": request.purpose,
        "user_id": request.user_id,
        "timestamp": datetime.now().isoformat()
    }

    payload_str = json.dumps(payload)
    mock_mode = False

    # Sign using HSM if available
    if hsm:
        try:
            signature = hsm.sign_data(None, payload_str.encode())
            signature_hex = signature.hex()
            key_label = "hsm_key"
        except Exception as e:
            logger.error(f"HSM signing failed: {e}")
            signature_hex = hashlib.sha256(payload_str.encode()).hexdigest()
            key_label = "fallback_key"
            mock_mode = True
    else:
        # Mock signing
        signature_hex = hashlib.sha256(payload_str.encode()).hexdigest()
        key_label = "mock_key"
        mock_mode = True

    # Log to audit if available
    if audit_logger:
        try:
            audit_logger.log_crypto_operation(
                "SIGN", key_label, request.user_id, request.aadhaar_ref)
        except:
            pass

    return AuthResponse(
        signed_request=payload_str,
        signature=signature_hex,
        key_label=key_label,
        timestamp=datetime.now().isoformat(),
        mock_mode=mock_mode
    )


@app.get("/admin/audit-log")
async def get_audit_log():
    """Retrieve audit logs"""
    if audit_logger:
        try:
            logs = audit_logger.get_recent_logs(100)
            return {"logs": logs, "hsm_available": hsm is not None}
        except:
            pass

    return {
        "logs": [{"id": 1, "timestamp": datetime.now().isoformat(), "operation": "test"}],
        "hsm_available": hsm is not None
    }


@app.get("/admin/keys")
async def list_keys():
    """List keys in HSM"""
    if hsm:
        try:
            keys = hsm.list_keys()
            return {"keys": keys, "hsm_available": True}
        except Exception as e:
            return {"keys": [], "error": str(e), "hsm_available": False}
    else:
        return {"keys": [{"label": "mock_key", "type": "RSA-2048"}], "hsm_available": False}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
