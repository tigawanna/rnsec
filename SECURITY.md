# Security Policy

## 🔒 Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in rnsec, please report it to us privately:

### How to Report

1. **Email**: Send details to **adnanpoviolabs@gmail.com**
2. **Subject**: "[SECURITY] Brief description"
3. **Include**:
   - Type of vulnerability
   - Full paths of source file(s) related to the issue
   - Location of the affected code (tag/branch/commit)
   - Step-by-step instructions to reproduce
   - Proof-of-concept or exploit code (if possible)
   - Impact of the issue

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Regular Updates**: Every 7 days until resolved
- **Credit**: You'll be credited in the security advisory (unless you prefer to remain anonymous)

## ⚠️ Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## 🛡️ Security Considerations for rnsec

### What rnsec Does

rnsec is a **static analysis tool** that:
- Reads source code files locally
- Analyzes code patterns
- Generates reports (HTML/JSON)
- Does NOT send data externally
- Does NOT execute analyzed code
- Does NOT require network access (except for npm install)

### Data Privacy

- **No telemetry**: We don't collect any usage data
- **Local only**: All scanning happens on your machine
- **No cloud**: No data is sent to external servers
- **Report control**: You control where reports are saved

### Safe Usage

✅ **Safe to use on:**
- Private codebases
- Proprietary code
- Code with secrets (though we'll flag them!)

⚠️ **Be careful with:**
- Sharing HTML/JSON reports (they contain code snippets)
- Committing reports to version control
- Sharing reports publicly

### Known Limitations

rnsec performs **static analysis** only:
- Cannot detect runtime vulnerabilities
- May have false positives/negatives
- Requires manual review of findings
- Should be part of a comprehensive security strategy

## 🔐 Dependencies Security

We use:
- Automated dependency scanning (Dependabot - planned)
- Regular dependency updates
- npm audit for vulnerability checking

Run security audit:
```bash
npm audit
```

## 🚨 Security Features in rnsec

rnsec helps you find:
- Hardcoded secrets and API keys
- Insecure storage patterns
- Weak cryptography
- Network security issues
- Authentication vulnerabilities
- And 63+ other security issues

But remember: **rnsec is a tool to help you, not a replacement for security experts.**

## 📋 Security Best Practices for Contributors

If you're contributing to rnsec:

1. **Never commit**:
   - Real API keys or secrets
   - Personal credentials
   - Production configurations

2. **Test files should**:
   - Use obviously fake data (e.g., `sk_test_FAKE...`)
   - Be in `examples/` directory
   - Be documented as test data

3. **Code reviews**:
   - Are required for all changes
   - Should check for security implications
   - Must verify no sensitive data is included

## 🏅 Security Hall of Fame

We'll recognize security researchers who responsibly disclose vulnerabilities:

*No vulnerabilities reported yet - be the first!*

## 📞 Contact

- **Security issues**: adnanpoviolabs@gmail.com
- **General questions**: GitHub Issues
- **Maintainer**: @adnxy

## 📝 Disclosure Policy

- We follow **coordinated disclosure**
- We'll work with you to understand and fix the issue
- We'll credit you in the security advisory
- We'll publish the fix before disclosing details

Thank you for helping keep rnsec and its users safe! 🙏

