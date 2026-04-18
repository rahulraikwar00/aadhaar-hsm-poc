import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from vault import Vault, AadhaarData
from token_manager import mask_aadhaar, mask_email, mask_phone


class TestVault:
    """Test vault storage functionality"""

    def setup_method(self):
        """Create fresh vault for each test"""
        self.vault = Vault()

    def test_store_data(self):
        """Test storing Aadhaar data"""
        data = AadhaarData(
            aadhaar_number="123456789012",
            name="Test User",
            email="test@example.com",
            phone="9876543210"
        )
        response = self.vault.store_data(data)

        assert response.token.startswith("T-")
        assert response.masked_aadhaar == "xxxxxxxx9012"
        assert response.created_at is not None

    def test_retrieve_data(self):
        """Test retrieving data by token"""
        data = AadhaarData(aadhaar_number="123456789012", name="Test")
        response = self.vault.store_data(data)

        retrieved = self.vault.retrieve_data(response.token)
        assert retrieved is not None
        assert retrieved.aadhaar_number == "123456789012"
        assert retrieved.name == "Test"

    def test_get_masked(self):
        """Test masked data retrieval"""
        data = AadhaarData(
            aadhaar_number="123456789012",
            email="test@example.com",
            phone="9876543210"
        )
        response = self.vault.store_data(data)

        masked = self.vault.get_masked(response.token)
        assert masked["aadhaar_number"] == "xxxxxxxx9012"
        assert masked["email"] == "txxt@example.com"
        assert masked["phone"] == "xxxxxx3210"

    def test_delete_data(self):
        """Test soft delete"""
        data = AadhaarData(aadhaar_number="123456789012", name="Test")
        response = self.vault.store_data(data)

        assert self.vault.delete_data(response.token) is True
        assert self.vault.retrieve_data(response.token) is None

    def test_check_duplicate(self):
        """Test duplicate detection"""
        data = AadhaarData(aadhaar_number="123456789012", name="Test")
        self.vault.store_data(data)

        assert self.vault.check_duplicate("123456789012") is True
        assert self.vault.check_duplicate("999988887777") is False

    def test_get_all_tokens(self):
        """Test listing all tokens"""
        data1 = AadhaarData(aadhaar_number="123456789012", name="Test1")
        data2 = AadhaarData(aadhaar_number="999988887777", name="Test2")

        self.vault.store_data(data1)
        self.vault.store_data(data2)

        tokens = self.vault.get_all_tokens()
        assert len(tokens) == 2

    def test_validate_token(self):
        """Test token validation"""
        data = AadhaarData(aadhaar_number="123456789012", name="Test")
        response = self.vault.store_data(data)

        assert self.vault.check_duplicate_by_token(response.token) is True
        self.vault.delete_data(response.token)
        assert self.vault.check_duplicate_by_token(response.token) is False


class TestTokenManager:
    """Test token manager functions"""

    def test_mask_aadhaar(self):
        """Test Aadhaar masking"""
        assert mask_aadhaar("123456789012") == "xxxxxxxx9012"
        assert mask_aadhaar("1234") == "xxxx"
        assert mask_aadhaar("12") == "xx"

    def test_mask_email(self):
        """Test email masking"""
        assert mask_email("test@example.com") == "txxt@example.com"
        assert mask_email("ab@example.com") == "xx@example.com"
        assert mask_email("a@example.com") == "x@example.com"
        assert mask_email("john.doe@example.com") == "jxxxxxxe@example.com"

    def test_mask_phone(self):
        """Test phone masking"""
        assert mask_phone("9876543210") == "xxxxxx3210"
        assert mask_phone("1234") == "xxxx"
        assert mask_phone("1") == "x"


class TestSecurity:
    """Test security validation"""

    def setup_method(self):
        try:
            from security import SecurityValidator
            self.validator = SecurityValidator()
        except ImportError:
            pytest.skip("Security module not available")

    def test_valid_aadhaar(self):
        """Test valid Aadhaar number"""
        is_valid, _ = self.validator.validate_aadhaar("123456789012")
        assert is_valid is True

    def test_invalid_aadhaar_short(self):
        """Test invalid Aadhaar - too short"""
        is_valid, _ = self.validator.validate_aadhaar("1234567890")
        assert is_valid is False

    def test_invalid_aadhaar_long(self):
        """Test invalid Aadhaar - too long"""
        is_valid, _ = self.validator.validate_aadhaar("1234567890123")
        assert is_valid is False

    def test_invalid_aadhaar_nondigits(self):
        """Test invalid Aadhaar - non-digits"""
        is_valid, _ = self.validator.validate_aadhaar("12345678a012")
        assert is_valid is False

    def test_valid_email(self):
        """Test valid email"""
        is_valid, _ = self.validator.validate_email("test@example.com")
        assert is_valid is True

    def test_invalid_email(self):
        """Test invalid email"""
        is_valid, _ = self.validator.validate_email("invalid-email")
        assert is_valid is False

    def test_valid_phone(self):
        """Test valid phone"""
        is_valid, _ = self.validator.validate_phone("9876543210")
        assert is_valid is True

    def test_invalid_phone(self):
        """Test invalid phone"""
        is_valid, _ = self.validator.validate_phone("123")
        assert is_valid is False

    def test_valid_name(self):
        """Test valid name"""
        is_valid, _ = self.validator.validate_name("John Doe")
        assert is_valid is True

    def test_invalid_name_special_chars(self):
        """Test invalid name with special characters"""
        is_valid, _ = self.validator.validate_name("John <script>")
        assert is_valid is False