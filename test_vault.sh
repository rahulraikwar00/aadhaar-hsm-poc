#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="http://localhost:8000"
PASS=0
FAIL=0

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_test() {
    echo -e "${YELLOW}Test: $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

wait_for_service() {
    local url=$1
    local name=$2
    echo "Waiting for $name..."
    for i in {1..30}; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo "$name is ready"
            return 0
        fi
        sleep 1
    done
    echo "$name failed to start"
    return 1
}

echo ""
print_header "Aadhaar Secure Vault - Test Suite"
echo ""

# Check if services are running
print_test "Checking if API is running..."
if curl -s "$API_URL/health" > /dev/null 2>&1; then
    print_pass "API is running"
else
    print_fail "API is not running"
    echo "Start services with: docker compose up -d"
    exit 1
fi

echo ""
print_header "1. Health & Info Tests"
echo ""

# Test health endpoint
print_test "GET /health"
RESP=$(curl -s "$API_URL/health")
if echo "$RESP" | grep -q "healthy"; then
    print_pass "Health endpoint"
else
    print_fail "Health endpoint: $RESP"
fi

# Test root endpoint
print_test "GET /"
RESP=$(curl -s "$API_URL/")
if echo "$RESP" | grep -q "running"; then
    print_pass "Root endpoint"
else
    print_fail "Root endpoint"
fi

echo ""
print_header "2. Vault Store Tests"
echo ""

# Test valid store
print_test "POST /vault/store (valid data)"
RESP=$(curl -s -X POST "$API_URL/vault/store" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "123456789012", "name": "John Doe", "email": "john@example.com", "phone": "9876543210"}')
TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -n "$TOKEN" ]; then
    print_pass "Store valid data (token: $TOKEN)"
else
    print_fail "Store valid data: $RESP"
fi

# Test invalid Aadhaar (not 12 digits)
print_test "POST /vault/store (invalid Aadhaar - 10 digits)"
RESP=$(curl -s -X POST "$API_URL/vault/store" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "1234567890"}')
if echo "$RESP" | grep -q "12 digits"; then
    print_pass "Validation: Aadhaar must be 12 digits"
else
    print_fail "Validation: $RESP"
fi

# Test invalid email
print_test "POST /vault/store (invalid email)"
RESP=$(curl -s -X POST "$API_URL/vault/store" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "999988887766", "email": "invalid-email"}')
if echo "$RESP" | grep -q "email"; then
    print_pass "Validation: Email format"
else
    print_fail "Validation: $RESP"
fi

# Store another record for testing
TEST_TOKEN=$(curl -s -X POST "$API_URL/vault/store" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "555566667777", "name": "Jane Doe"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

echo ""
print_header "3. Vault Retrieve Tests"
echo ""

if [ -n "$TOKEN" ]; then
    # Test retrieve
    print_test "GET /vault/{token}"
    RESP=$(curl -s "$API_URL/vault/$TOKEN")
    if echo "$RESP" | grep -q "123456789012"; then
        print_pass "Retrieve data"
    else
        print_fail "Retrieve: $RESP"
    fi

    # Test masked
    print_test "GET /vault/{token}/masked"
    RESP=$(curl -s "$API_URL/vault/$TOKEN/masked")
    if echo "$RESP" | grep -q "xxxxxxxx"; then
        print_pass "Masked data contains xxxx"
        if echo "$RESP" | grep -q "jxxxxxr@example.com"; then
            print_pass "Email masked correctly"
        fi
    else
        print_fail "Masked: $RESP"
    fi

    # Test validate
    print_test "GET /vault/{token}/validate"
    RESP=$(curl -s "$API_URL/vault/$TOKEN/validate")
    if echo "$RESP" | grep -q '"is_valid":true'; then
        print_pass "Token validation"
    else
        print_fail "Validate: $RESP"
    fi
fi

echo ""
print_header "4. Vault Operations Tests"
echo ""

# Test duplicate check - should find existing
print_test "POST /vault/check-duplicate (existing)"
RESP=$(curl -s -X POST "$API_URL/vault/check-duplicate" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "123456789012"}')
if echo "$RESP" | grep -q '"is_duplicate":true'; then
    print_pass "Duplicate check finds existing"
else
    print_fail "Duplicate check: $RESP"
fi

# Test duplicate check - should not find
print_test "POST /vault/check-duplicate (new)"
RESP=$(curl -s -X POST "$API_URL/vault/check-duplicate" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_number": "111122223344"}')
if echo "$RESP" | grep -q '"is_duplicate":false'; then
    print_pass "Duplicate check for new record"
else
    print_fail "Duplicate check: $RESP"
fi

# Test list tokens
print_test "GET /vault/tokens"
RESP=$(curl -s "$API_URL/vault/tokens")
COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
if [ "$COUNT" -gt 0 ]; then
    print_pass "List tokens (count: $COUNT)"
else
    print_fail "List tokens: $RESP"
fi

# Test delete
if [ -n "$TOKEN" ]; then
    print_test "DELETE /vault/{token}"
    RESP=$(curl -s -X DELETE "$API_URL/vault/$TOKEN")
    if echo "$RESP" | grep -q "deleted"; then
        print_pass "Delete data"
    else
        print_fail "Delete: $RESP"
    fi

    # Test validate after delete
    print_test "GET /vault/{token}/validate (after delete)"
    RESP=$(curl -s "$API_URL/vault/$TOKEN/validate")
    if echo "$RESP" | grep -q '"is_valid":false'; then
        print_pass "Token invalid after delete"
    else
        print_fail "Validate after delete: $RESP"
    fi
fi

echo ""
print_header "5. Auth Sign Tests"
echo ""

# Test auth sign
print_test "POST /auth/sign"
RESP=$(curl -s -X POST "$API_URL/auth/sign" \
    -H "Content-Type: application/json" \
    -d '{"aadhaar_ref": "TEST-123", "biometric_data": "test", "user_id": "user1", "purpose": "test"}')
if echo "$RESP" | grep -q "signature"; then
    print_pass "Auth sign"
else
    print_fail "Auth sign: $RESP"
fi

echo ""
print_header "6. Metrics Tests"
echo ""

# Test metrics endpoint
print_test "GET /metrics"
RESP=$(curl -s "$API_URL/metrics")
if echo "$RESP" | grep -q "vault_store_total"; then
    print_pass "Metrics endpoint"
    STORE_COUNT=$(echo "$RESP" | grep "vault_store_total" | grep -o "[0-9]\+\.[0-9]\+" | cut -d. -f1)
    echo "  - vault_store_total: $STORE_COUNT"
else
    print_fail "Metrics: No vault metrics found"
fi

echo ""
print_header "Summary"
echo ""
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi