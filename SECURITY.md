# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | Yes (current)      |

## Reporting a Vulnerability

KavachOS takes security seriously. If you discover a security vulnerability, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

Email **security@kavachos.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Any suggested fixes (optional)

### What to expect

- **Acknowledgment** within 48 hours
- **Assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Credit** in the security advisory (unless you prefer anonymity)

### Scope

The following are in scope:
- Authentication bypass
- Authorization flaws (permission escalation, delegation bypass)
- Token leakage or prediction
- Session fixation or hijacking
- SQL injection
- Cross-site scripting (XSS) in UI components
- Cross-site request forgery (CSRF) bypass
- Cryptographic weaknesses
- Information disclosure

### Out of scope

- Denial of service (DoS)
- Social engineering
- Issues in dependencies (report to the upstream project)
- Issues requiring physical access

## Security best practices

When using KavachOS in production:

1. **Always use HTTPS** in production
2. **Set strong session secrets** - never use defaults
3. **Enable rate limiting** to prevent brute force
4. **Use HIBP checking** for password breach detection
5. **Enable TOTP or passkeys** for admin accounts
6. **Rotate API keys** regularly
7. **Monitor the audit trail** for anomalies
8. **Keep kavachos updated** to the latest version

## Dependencies

KavachOS has only 3 runtime dependencies:
- `drizzle-orm` - SQL query builder
- `jose` - JWT/JWS/JWE implementation
- `zod` - Schema validation

We actively monitor these for vulnerabilities via GitHub Dependabot.
