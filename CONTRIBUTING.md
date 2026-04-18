# Contributing to Aadhaar Secure Vault

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs
1. Search existing issues first
2. Create issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details

### Suggesting Features
1. Open discussion issue first
2. Describe the use case
3. Explain expected behavior

### Pull Requests

**Before submitting:**
- Fork the repository
- Create a feature branch: `git checkout -b feature/your-feature`
- Run tests: `./test_vault.sh`
- Ensure code follows existing style

**PR guidelines:**
- Keep changes focused and atomic
- Update documentation if needed
- Add tests for new functionality
- Ensure all tests pass before submitting

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aadhaar-hsm-poc.git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
./test_vault.sh

# Run locally
docker compose up -d
```

### Code Style

- Python: Follow PEP 8
- Use type hints where helpful
- Add docstrings for new functions
- Keep lines under 100 characters

### Security Considerations

- Never commit secrets or credentials
- Use environment variables for sensitive config
- Follow the security guidelines in SECURITY.md

## Questions?

Open an issue for questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.