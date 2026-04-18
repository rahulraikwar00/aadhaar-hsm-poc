# Aadhaar Secure Vault

A self-installable, open-source proof-of-concept for secure on-premises Aadhaar storage using tokenization and HSM-backed encryption.

## Overview

This project implements a **Tokenization + Vault Architecture** for securely storing and managing Aadhaar data:

- **Tokenization**: Sensitive Aadhaar data is replaced with secure tokens (T-UUID format)
- **Vault**: Encrypted storage with field-level masking
- **HSM Integration**: Hardware Security Module for cryptographic operations
- **Audit Logging**: Complete audit trail of all operations

### Key Features

- Token-based storage (no raw Aadhaar exposed)
- Field-level data masking (Aadhaar, email, phone)
- Input validation (Aadhaar format, email, phone)
- Secure delete (soft delete, data not immediately removed)
- Duplicate detection
- Prometheus metrics
- Grafana dashboard support

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    hsm-network (bridge)                          │
│                                                                │
│   ┌──────────────────┐      ┌──────────────────┐                │
│   │   grafana:3000   │      │ prometheus:9090  │                │
│   │  (Dashboards)   │◄─────│  (Metrics)      │                │
│   └──────────────────┘      └────────┬─────────┘                │
│            │                              │                       │
│            │                       ┌─────┴─────────┐             │
│            │                       │    app:8000  │             │
│            │                       │ (FastAPI)   │             │
│            │                       └──────┬──────┘             │
│      ┌─────┴──────┐                    │                      │
│      │ softhsm     │                    │  ┌───────────────┐    │
│      │ (HSM)      │◄───────────────────┴──│  │ audit-db:5432 │    │
│      └────────────┘                       │  │ (PostgreSQL)  │    │
│                                       │  └─────────────┘    │
└────────────────────────────────────────┴─────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker
- Docker Compose

### Installation

```bash
# Clone and navigate
cd aadhaar-secure-vault

# Start all services
docker compose up -d

# Check status
docker compose ps
```

### Test the API

```bash
# Health check
curl http://localhost:8000/health

# Store Aadhaar data (returns token)
curl -X POST http://localhost:8000/vault/store \
  -H "Content-Type: application/json" \
  -d '{
    "aadhaar_number": "123456789012",
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "9876543210"
  }'

# Retrieve by token
curl http://localhost:8000/vault/{TOKEN}

# Get masked data only
curl http://localhost:8000/vault/{TOKEN}/masked

# Check for duplicates
curl -X POST http://localhost:8000/vault/check-duplicate \
  -H "Content-Type: application/json" \
  -d '{"aadhaar_number": "123456789012"}'

# List all tokens
curl http://localhost:8000/vault/tokens

# Delete data (soft delete)
curl -X DELETE http://localhost:8000/vault/{TOKEN}

# Validate token
curl http://localhost:8000/vault/{TOKEN}/validate
```

## API Endpoints

### Vault Operations

| Method | Endpoint | Description |
|--------|---------|-------------|
| POST | `/vault/store` | Store Aadhaar → get token |
| GET | `/vault/{token}` | Retrieve full data |
| GET | `/vault/{token}/masked` | Get masked data |
| GET | `/vault/{token}/validate` | Check token validity |
| DELETE | `/vault/{token}` | Secure delete |
| POST | `/vault/check-duplicate` | Check if exists |
| GET | `/vault/tokens` | List all tokens |
| GET | `/vault/audit` | Audit logs |

### Other Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET | `/` | Service info |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |
| POST | `/auth/sign` | Sign auth request |
| GET | `/admin/keys` | List HSM keys |

## Security Features

### Input Validation
- Aadhaar number: Exactly 12 digits
- Email: RFC 5322 format
- Phone: 10-12 digits
- Name: No special characters

### Data Masking
- Aadhaar: `xxxxxxxx9012` (last 4 visible)
- Email: `jxxxxxr@example.com`
- Phone: `xxxxxx3210`

### Sensitive Data Filter
Automatically redacts sensitive fields in logs:
- `aadhaar_number`
- `biometric_data`
- `password`, `pin`, `secret`, `token`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HSM_LIBRARY` | `/usr/lib/softhsm/libsofthsm2.so` | SoftHSM library |
| `HSM_TOKEN_LABEL` | `AuthToken` | HSM token label |
| `HSM_USER_PIN` | `12345678` | HSM user PIN |
| `DB_HOST` | `postgres` | Database host |
| `DB_NAME` | `aadhaar_audit` | Database name |
| `DB_USER` | `audit_user` | Database user |
| `DB_PASSWORD` | `AuditPass2025!` | Database password |
| `API_PORT` | `8000` | API port |

## Services

| Service | Port | Credentials |
|---------|-----|------------|
| API | 8000 | - |
| Prometheus | 9090 | - |
| Grafana | 3000 | admin/admin123 |
| PostgreSQL | 5432 | audit_user/AuditPass2025! |

## Prometheus Metrics

```bash
# View all metrics
curl http://localhost:8000/metrics

# Query specific metrics
vault_store_total           # Total store operations
vault_retrieve_total      # Total retrieve operations
vault_delete_total      # Total delete operations
auth_requests_total    # Auth requests
hsm_signatures_total  # HSM signatures
```

## Grafana Setup

1. Open http://localhost:3000
2. Login: `admin` / `admin123`
3. Add data source:
   - Configuration → Data Sources → Add
   - Select Prometheus
   - URL: `http://prometheus:9090`
4. Create dashboard with queries:
   - `vault_store_total`
   - `vault_retrieve_total`
   - `rate(vault_store_total[5m])`

## Running Tests

```bash
# Run full test suite
./test_vault.sh

# Expected output: All 16 tests passed
```

## Project Structure

```
aadhaar-hsm-poc/
├── app/
│   ├── main.py              # FastAPI application
│   ├── hsm_wrapper.py     # SoftHSM wrapper
│   ├── vault.py           # Vault storage
│   ├── token_manager.py  # Tokenization
│   ├── security.py       # Validation & filtering
│   ├── audit_logger.py # Audit logging
│   └── key_rotation_manager.py
├── postgress/
│   └── init.sql
├── prometheus/
│   └── prometheus.yml
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env
├── config.yaml
├── README.md
├── architecture.mmd
├── architecture.png
└── test_vault.sh          # Test script for validation
```
```

## Testing

### Using Test Script

```bash
# Run the test script
./test_vault.sh

# Or run manually
```

### Manual Tests

```bash
# Test store
curl -X POST http://localhost:8000/vault/store \
  -H "Content-Type: application/json" \
  -d '{"aadhaar_number": "123456789012", "name": "Test"}'

# Test validation
curl -X POST http://localhost:8000/vault/store \
  -H "Content-Type: application/json" \
  -d '{"aadhaar_number": "123"}'  # Should fail

# Test metrics
curl http://localhost:8000/metrics | grep vault
```

### Build Docker

```bash
docker compose build app
docker compose up -d
```

### View Logs

```bash
docker compose logs app
docker compose logs softhsm
docker compose logs postgres
```

## Stopping

```bash
docker compose down
docker compose down -v  # Remove volumes
```

## Roadmap

- [ ] PostgreSQL-backed vault (production)
- [ ] HSM field encryption
- [ ] Correlation ID audit logging
- [ ] Key rotation
- [ ] TLS/HTTPS
- [ ] API authentication
- [ ] Rate limiting

## License

MIT