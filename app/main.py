from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import json
import hashlib
import os
import logging
from prometheus_client import Counter, Gauge, generate_latest
from starlette.responses import Response
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_requests_total = Counter('auth_requests_total', 'Total auth requests')
key_rotations_total = Counter('key_rotations_total', 'Total key rotations')
hsm_signatures_total = Counter('hsm_signatures_total', 'Total HSM signatures')
mock_signatures_total = Counter('mock_signatures_total', 'Total mock signatures')
hsm_connected = Gauge('hsm_connected', 'HSM connection status (1=connected)')

vault_store_total = Counter('vault_store_total', 'Total vault store operations')
vault_retrieve_total = Counter('vault_retrieve_total', 'Total vault retrieve operations')
vault_delete_total = Counter('vault_delete_total', 'Total vault delete operations')
vault_duplicate_check_total = Counter('vault_duplicate_check_total', 'Total duplicate check operations')

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

try:
    from db_vault import create_vault, AadhaarData, TokenResponse
    logger.info("DB Vault module imported")
    DB_VAULT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"DB Vault module not available: {e}")
    DB_VAULT_AVAILABLE = False

try:
    from vault import vault, AadhaarData as InMemoryAadhaarData
    logger.info("In-memory Vault module imported")
    VAULT_FALLBACK = True
except ImportError as e:
    logger.warning(f"In-memory Vault module not available: {e}")
    VAULT_FALLBACK = False

try:
    from security import SecurityValidator, SensitiveDataFilter
    logger.info("Security validator imported")
    SECURITY_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Security validator not available: {e}")
    SECURITY_AVAILABLE = False

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
        if hsm and hsm.session:
            hsm_connected.set(1)
            logger.info("HSM initialized")
        else:
            hsm_connected.set(0)
            logger.warning("HSM initialized but no session")

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

# Initialize vault (PostgreSQL or fallback to in-memory)
vault = None
if DB_VAULT_AVAILABLE:
    try:
        # Get HSM session for encryption
        hsm_session = hsm.session if hsm else None
        
        vault = create_vault(
            db_host=os.getenv('DB_HOST', 'postgres'),
            db_name=os.getenv('DB_NAME', 'aadhaar_audit'),
            db_user=os.getenv('DB_USER', 'audit_user'),
            db_password=os.getenv('DB_PASSWORD', 'AuditPass2025!'),
            hsm_session=hsm_session
        )
        logger.info("Database vault initialized")
    except Exception as e:
        logger.warning(f"Database vault initialization failed: {e}")
        if VAULT_FALLBACK:
            vault = vault
            logger.info("Using in-memory vault fallback")
else:
    if VAULT_FALLBACK:
        vault = vault
        logger.info("Using in-memory vault fallback")


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


class VaultStoreRequest(BaseModel):
    aadhaar_number: str
    name: Optional[str] = None
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    biometric_data: Optional[str] = None
    user_id: str = "system"


class VaultStoreResponse(BaseModel):
    token: str
    masked_aadhaar: str
    created_at: str
    message: str = "Data stored successfully"


class VaultRetrieveResponse(BaseModel):
    token: str
    aadhaar_number: str
    name: Optional[str] = None
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None


class VaultCheckDuplicateRequest(BaseModel):
    aadhaar_number: str


class VaultCheckDuplicateResponse(BaseModel):
    is_duplicate: bool
    token: Optional[str] = None


@app.get("/vault/audit")
async def vault_audit(token: str = None, limit: int = 100):
    """Get audit log of vault operations"""
    if audit_logger and hasattr(audit_logger, 'get_vault_logs'):
        logs = audit_logger.get_vault_logs(token, limit)
        return {"logs": logs, "count": len(logs)}
    return {"logs": [], "count": 0, "message": "Audit logging not available"}


class VaultAuditResponse(BaseModel):
    token: str
    operation: str
    timestamp: str


@app.get("/vault/{token}", response_model=VaultRetrieveResponse)
async def vault_retrieve(token: str):
    """Retrieve Aadhaar data by token"""
    vault_retrieve_total.inc()

    try:
        data = vault.retrieve_data(token)
        if not data:
            raise HTTPException(status_code=404, detail="Token not found or deleted")

        # Log to audit
        if audit_logger and hasattr(audit_logger, 'log_vault_operation'):
            audit_logger.log_vault_operation("RETRIEVE", token, "system", {})

        return VaultRetrieveResponse(
            token=token,
            aadhaar_number=data.aadhaar_number,
            name=data.name,
            date_of_birth=data.date_of_birth,
            gender=data.gender,
            address=data.address,
            phone=data.phone,
            email=data.email
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vault retrieve failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vault/{token}/masked")
async def vault_get_masked(token: str):
    """Get masked Aadhaar data by token"""
    masked = vault.get_masked(token)
    if not masked:
        raise HTTPException(status_code=404, detail="Token not found or deleted")
    return masked


@app.delete("/vault/{token}")
async def vault_delete(token: str):
    """Secure delete Aadhaar data by token"""
    vault_delete_total.inc()

    success = vault.delete_data(token)
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")

    # Log to audit
    if audit_logger and hasattr(audit_logger, 'log_vault_operation'):
        audit_logger.log_vault_operation("DELETE", token, "system", {})

    return {"message": "Data deleted successfully", "token": token}


@app.get("/vault/{token}/validate")
async def vault_validate_token(token: str):
    """Validate a token (check if exists and not deleted)"""
    is_valid = vault.check_duplicate_by_token(token)
    return {
        "token": token,
        "is_valid": is_valid,
        "status": "active" if is_valid else "not_found_or_deleted"
    }


class VaultAuditResponse(BaseModel):
    token: str
    operation: str
    timestamp: str


@app.get("/vault/audit")
async def vault_audit(token: str = None, limit: int = 100):
    """Get audit log of vault operations"""
    if audit_logger and hasattr(audit_logger, 'get_vault_logs'):
        logs = audit_logger.get_vault_logs(token, limit)
        return {"logs": logs, "count": len(logs)}
    return {"logs": [], "count": 0, "message": "Audit logging not available"}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
