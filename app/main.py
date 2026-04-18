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
    from vault import vault, AadhaarData, TokenResponse
    logger.info("Vault module imported")
except ImportError as e:
    logger.warning(f"Vault module not available: {e}")

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


class VaultAuditResponse(BaseModel):
    token: str
    operation: str
    timestamp: str


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
    auth_requests_total.inc()

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
            hsm_signatures_total.inc()
        except Exception as e:
            logger.error(f"HSM signing failed: {e}")
            signature_hex = hashlib.sha256(payload_str.encode()).hexdigest()
            key_label = "fallback_key"
            mock_mode = True
            mock_signatures_total.inc()
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


@app.post("/vault/store", response_model=VaultStoreResponse)
async def vault_store(request: VaultStoreRequest):
    """Store Aadhaar data in vault and generate token"""
    vault_store_total.inc()

    try:
        from vault import AadhaarData

        if SECURITY_AVAILABLE:
            is_valid, error = SecurityValidator.validate_aadhaar(request.aadhaar_number)
            if not is_valid:
                raise HTTPException(status_code=400, detail=error)

            if request.email:
                is_valid, error = SecurityValidator.validate_email(request.email)
                if not is_valid:
                    raise HTTPException(status_code=400, detail=error)

            if request.phone:
                is_valid, error = SecurityValidator.validate_phone(request.phone)
                if not is_valid:
                    raise HTTPException(status_code=400, detail=error)

            if request.name:
                is_valid, error = SecurityValidator.validate_name(request.name)
                if not is_valid:
                    raise HTTPException(status_code=400, detail=error)

        aadhaar_data = AadhaarData(
            aadhaar_number=request.aadhaar_number,
            name=request.name,
            date_of_birth=request.date_of_birth,
            gender=request.gender,
            address=request.address,
            phone=request.phone,
            email=request.email,
            biometric_data=request.biometric_data
        )

        response = vault.store_data(aadhaar_data, request.user_id)
        logger.info(f"Vault store: token={response.token}")

        return VaultStoreResponse(
            token=response.token,
            masked_aadhaar=response.masked_aadhaar,
            created_at=response.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vault store failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vault/tokens")
async def vault_list_tokens():
    """List all valid tokens"""
    tokens = vault.get_all_tokens()
    return {"tokens": tokens, "count": len(tokens)}


@app.post("/vault/check-duplicate", response_model=VaultCheckDuplicateResponse)
async def vault_check_duplicate(request: VaultCheckDuplicateRequest):
    """Check if Aadhaar number already exists"""
    vault_duplicate_check_total.inc()

    is_duplicate = vault.check_duplicate(request.aadhaar_number)
    if is_duplicate:
        for token in vault.get_all_tokens():
            data = vault.retrieve_data(token)
            if data and data.aadhaar_number == request.aadhaar_number:
                return VaultCheckDuplicateResponse(
                    is_duplicate=True,
                    token=token
                )

    return VaultCheckDuplicateResponse(is_duplicate=False)


@app.get("/vault/{token}", response_model=VaultRetrieveResponse)
async def vault_retrieve(token: str):
    """Retrieve Aadhaar data by token"""
    vault_retrieve_total.inc()

    try:
        data = vault.retrieve_data(token)
        if not data:
            raise HTTPException(status_code=404, detail="Token not found or deleted")

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
async def vault_audit(limit: int = 100):
    """Get audit log of vault operations"""
    return {
        "message": "Audit endpoint - implement with correlation IDs",
        "note": "Add correlation ID tracking for production"
    }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
