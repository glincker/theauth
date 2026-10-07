# Security Policy

## Supported Versions

Packages in this repo are versioned independently and are mostly pre-1.0. Security fixes go to the latest release line of each package:

| Package | Supported line |
| ------- | -------------- |
| `@glinr/theauth` (core) | 0.5.x |
| `@glinr/theauth-react` | 0.6.x |
| `@glinr/theauth-client`, `-vue`, `-svelte`, `-expo`, `-electron` | 0.2.x |
| `@glinr/theauth-gateway` | 3.0.x |
| `@glinr/theauth-cli`, `@glinr/theauth-dashboard` | 0.1.x |
| `@glinr/theauth-ui`, `-ui-headless`, `-test-utils` | 0.1.x |
| Older lines | No |

## Reporting a Vulnerability

TheAuth takes security seriously. If you discover a security vulnerability, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

**Option 1 (preferred):** Use GitHub's private vulnerability reporting:
[github.com/glincker/theauth/security/advisories/new](https://github.com/glincker/theauth/security/advisories/new)

**Option 2:** Email **support@glinr.com** with the subject `[Security] theauth vulnerability` and include:

1. Description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Any suggested fixes (optional)

### What to expect

- **Acknowledgment** within 48 hours
- **Assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Public disclosure** within 90 days of confirmation, coordinated with the reporter. If a fix cannot ship in that window, we will still disclose so users can mitigate.
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

When using TheAuth in production:

1. **Always use HTTPS** in production
2. **Set strong session secrets** - never use defaults
3. **Enable rate limiting** to prevent brute force
4. **Use HIBP checking** for password breach detection
5. **Enable TOTP or passkeys** for admin accounts
6. **Rotate API keys** regularly
7. **Monitor the audit trail** for anomalies
8. **Keep theauth updated** to the latest version

## Dependencies

TheAuth has only 3 runtime dependencies:
- `drizzle-orm` - SQL query builder
- `jose` - JWT/JWS/JWE implementation
- `zod` - Schema validation

We actively monitor these for vulnerabilities via GitHub Dependabot.
