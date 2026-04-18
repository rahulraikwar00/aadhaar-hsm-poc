# Security Policy

## Reporting Vulnerabilities

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email security reports to: [security contact placeholder - add your email]
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Update**: Every 14 days until resolution
- **Public Disclosure**: After patch release (with coordination)

## Security Considerations

### This Project Is A Proof-of-Concept

⚠️ **Important**: This software is provided as a **proof-of-concept** for educational and development purposes. It is **NOT** production-ready and should NOT be used in live Aadhaar data processing without:

- Comprehensive security audit
- Implementation of additional safeguards
- Compliance with UIDAI guidelines
- Legal approval for handling Aadhaar data

### Known Limitations

1. **HSM Compatibility**: SoftHSM is used for development; production requires hardware HSM
2. **Encryption**: Current implementation uses AES-GCM but may need additional hardening
3. **No API Authentication**: Currently no authentication on endpoints
4. **No Rate Limiting**: Vulnerable to abuse without proper configuration

### Security Best Practices for Deployment

1. **Use Hardware HSM** (Thales, Utimco, etc.) for production
2. **Enable TLS/HTTPS** before deploying
3. **Implement API authentication** (OAuth2, API keys)
4. **Configure firewall** to restrict access
5. **Enable audit logging** for all operations
6. **Regular key rotation** procedures
7. **Network isolation** - run in private network/VPC

### Data Protection

- Aadhaar numbers are stored as tokens, not plaintext
- Field-level masking applied to sensitive data
- SHA-256 hashing for duplicate detection
- Soft-delete for data removal (audit trail)

### Dependency Security

This project uses the following key dependencies. Ensure you keep them updated:

- `python-pkcs11` - HSM interface
- `psycopg2` - PostgreSQL driver
- `fastapi` - Web framework
- `cryptography` - Encryption primitives

### License

This project is licensed under the MIT License - see LICENSE file for details.

---

**Disclaimer**: This software is provided "as is" without warranty of any kind. Use at your own risk.