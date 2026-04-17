#!/bin/bash

echo "Testing Aadhaar HSM Gateway..."

# Test health endpoint
echo -e "\n1. Health Check:"
curl -s http://localhost:8000/health | jq

# Test signing
echo -e "\n2. Sign Auth Request:"
SIGN_RESPONSE=$(curl -s -X POST http://localhost:8000/auth/sign \
  -H "Content-Type: application/json" \
  -d '{
    "aadhaar_ref": "TEST-12345",
    "biometric_data": "test_biometric_data",
    "user_id": "user001",
    "purpose": "testing"
  }')
echo $SIGN_RESPONSE | jq

# Get audit log
echo -e "\n3. Audit Log:"
curl -s http://localhost:8000/admin/audit-log?limit=5 | jq

# List HSM keys
echo -e "\n4. HSM Keys:"
curl -s http://localhost:8000/admin/keys | jq

# Get Prometheus metrics
echo -e "\n5. Metrics:"
curl -s http://localhost:8000/metrics | grep -E "auth_requests_total|key_rotations_total"
