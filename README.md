# rnsec

**🔒 Security Scanner for React Native & Expo**

Find vulnerabilities in your mobile app with zero configuration.  
63 security rules • 27+ API key patterns • Android & iOS specific checks

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#security-checks">Security Checks</a> •
  <a href="#cicd-integration">CI/CD</a> •
  <a href="#examples">Examples</a>
</p>

---

## Why rnsec?

- **🎯 Simple**: One command, instant results
- **📊 Comprehensive**: 63 security rules across 13 categories  
- **🔑 Smart**: Detects 27+ types of exposed API keys and secrets
- **📱 Mobile-Ready**: Android & iOS platform-specific checks
- **⚡ Fast**: Scans entire projects in seconds

## Installation

```bash
npm install -g rnsec
```

Or install from source:

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/adnxy/rnsec.git
cd rnsec
npm install
npm run build
npm link
```
</details>

## Quick Start

### 1. Run Scan
```bash
rnsec scan
```

### 2. Get Results
Automatically generated:
-  **`rnsec-report.html`** - Interactive web dashboard
-  **`rnsec-report.json`** - Data for CI/CD pipelines
-  **Console output** - Instant summary

### 3. Review Findings
```bash
open rnsec-report.html    # View in browser
```

## Usage

### Default Behavior

By default, `rnsec scan` generates **both reports automatically**:
- `rnsec-report.html` - Interactive web report with filtering
- `rnsec-report.json` - Machine-readable results

```bash
# Scan current directory
rnsec scan

# Scan specific project
rnsec scan --path ./my-react-native-app
```

### Custom Output

```bash
# Custom HTML filename
rnsec scan --html my-security-report.html

# Custom JSON filename  
rnsec scan --output results.json

# Both custom filenames
rnsec scan --html report.html --output data.json

# Console output only (no files)
rnsec scan --json

# Silent mode (minimal output)
rnsec scan --silent
```

### CI/CD Mode

```bash
# Generate JSON for CI/CD pipeline
rnsec scan --output security-results.json --silent
```

### View All Rules

```bash
# List all 62 security rules
rnsec rules
```

### Command Reference

```bash
rnsec scan [options]

Options:
  -p, --path <path>        Project directory (default: current directory)
  --html <filename>        Custom HTML report filename
  --output <filename>      Custom JSON report filename
  --json                   Console JSON output only (no files)
  --silent                 Suppress console output
  -h, --help              Show help
```

## Security Checks

rnsec includes **63 security rules** organized into 13 categories:

| Category | Rules | Key Checks |
|----------|-------|------------|
| 🔐 **Storage** | 6 | AsyncStorage sensitive data, hardcoded secrets, PII encryption, file storage |
| 🌐 **Network** | 13 | HTTP usage, WebView security, SSL/TLS configuration, timeouts |
| 🔑 **Authentication** | 6 | JWT validation, biometric fallback, certificate pinning |
| 🔐 **Cryptography** | 2 | Weak algorithms (MD5/SHA1), hardcoded keys |
| 📝 **Logging** | 2 | Sensitive data in logs, error message exposure |
| 📱 **React Native** | 10 | Bridge security, deep links, eval() usage, deserialization |
| 🔓 **Secrets** | 2 | API keys (27+ patterns), exposed credentials |
| 🐛 **Debug** | 3 | Test credentials, debug endpoints, dev tools |
| 📱 **Android** | 8 | Manifest misconfigurations, Keystore security, permissions |
| 📱 **iOS** | 8 | Info.plist issues, Keychain security, ATS exceptions |
| ⚙️ **Configuration** | 1 | Dangerous permissions |
| 📄 **Manifest** | 2 | Platform manifests and configuration files |

<details>
<summary><strong>View All 63 Rules</strong></summary>

### 🔐 Storage Security (6 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `ASYNCSTORAGE_SENSITIVE_KEY` | HIGH | Detects sensitive data stored in AsyncStorage (tokens, passwords, credentials) |
| `HARDCODED_SECRETS` | HIGH | Identifies hardcoded API keys, JWT tokens, AWS credentials, and secrets |
| `ASYNCSTORAGE_PII_DATA` | HIGH | AsyncStorage storing PII (email, phone, SSN) without encryption |
| `REDUX_PERSIST_NO_ENCRYPTION` | MEDIUM | Redux persist configuration without encryption transform for sensitive data |
| `CLIPBOARD_SENSITIVE_DATA` | MEDIUM | Sensitive data copied to clipboard (accessible by other apps) |
| `INSECURE_FILE_STORAGE` | MEDIUM | Files written to insecure storage locations without encryption |

### 🌐 Network Security (13 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_HTTP_URL` | MEDIUM | Detects HTTP URLs in fetch(), axios, and API calls (should use HTTPS) |
| `INSECURE_WEBVIEW` | HIGH | Identifies WebView components with dangerous configurations |
| `WEBVIEW_JAVASCRIPT_INJECTION` | HIGH | WebView with JavaScript enabled loading dynamic or user-controlled content |
| `WEBVIEW_FILE_ACCESS` | HIGH | WebView with file access enabled - allows access to local files |
| `WEBVIEW_DOM_STORAGE_ENABLED` | MEDIUM | WebView with DOM storage enabled - may expose sensitive data |
| `WEBVIEW_GEOLOCATION_ENABLED` | MEDIUM | WebView with geolocation enabled - requires proper permission handling |
| `WEBVIEW_MIXED_CONTENT` | MEDIUM | WebView allows mixed content - HTTPS pages can load HTTP resources |
| `WEBVIEW_UNVALIDATED_NAVIGATION` | HIGH | WebView without URL validation on navigation - potential open redirect |
| `WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK` | HIGH | WebView onMessage handler without origin validation |
| `WEBVIEW_CACHING_ENABLED` | LOW | WebView caching enabled for authenticated/sensitive content |
| `MISSING_SECURITY_HEADERS` | LOW | WebView missing important security headers (CSP, X-Frame-Options) |
| `NO_REQUEST_TIMEOUT` | MEDIUM | Network request without timeout configuration - DoS risk |
| `WEAK_TLS_CONFIGURATION` | MEDIUM | Weak TLS configuration (TLS < 1.2, weak ciphers, disabled validation) |
| `WEBVIEW_CACHING_ENABLED` | LOW | WebView with caching enabled - may cache sensitive content |

### 🔑 Authentication & Authorization (6 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `INSECURE_RANDOM` | HIGH | Math.random() used in security contexts (tokens, keys, passwords) - context-aware |
| `JWT_NO_EXPIRY_CHECK` | MEDIUM | JWT token retrieved from storage without expiration validation |
| `TEXT_INPUT_NO_SECURE` | MEDIUM | TextInput for passwords without secureTextEntry property |
| `OAUTH_TOKEN_IN_URL` | HIGH | OAuth/access token passed in URL query parameters |
| `CERT_PINNING_DISABLED` | MEDIUM | SSL certificate pinning disabled or bypassed |
| `IMPROPER_BIOMETRIC_FALLBACK` | MEDIUM | Biometric authentication with insecure fallback mechanism |

### 🔐 Cryptography (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `WEAK_HASH_ALGORITHM` | HIGH | Detects weak hashing algorithms (MD5, SHA1) |
| `HARDCODED_ENCRYPTION_KEY` | HIGH | Identifies hardcoded encryption keys and IVs |

### 📝 Logging (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `SENSITIVE_LOGGING` | MEDIUM | Detects console.log() statements containing sensitive data |
| `SENSITIVE_DATA_IN_ERROR_MESSAGES` | MEDIUM | Error messages or stack traces exposing sensitive data |

### 📱 React Native Specific (10 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `JAVASCRIPT_ENABLED_BRIDGE` | HIGH | Detects dangerous JavaScript bridge interactions with native modules |
| `INSECURE_DEEPLINK_HANDLER` | HIGH | Detects deep link handlers without proper URL validation |
| `SCREENSHOT_PROTECTION_MISSING` | MEDIUM | Sensitive screen without screenshot/screen recording protection |
| `UNSAFE_DANGEROUSLY_SET_INNER_HTML` | HIGH | dangerouslySetInnerHTML used with potentially unsafe content |
| `NETWORK_LOGGER_IN_PRODUCTION` | MEDIUM | Network request/response logging enabled - may expose sensitive data |
| `EVAL_USAGE` | HIGH | eval() used - code injection risk |
| `ROOT_JAILBREAK_DETECTION_ABSENT` | HIGH | Sensitive app (banking/fintech/healthcare) without root/jailbreak detection |
| `MISSING_RUNTIME_INTEGRITY_CHECKS` | MEDIUM | No runtime integrity or tamper detection implemented |
| `INSECURE_DESERIALIZATION` | HIGH | Unsafe deserialization of untrusted data (JSON.parse without validation) |
| `THIRD_PARTY_SDK_RISK` | LOW | Potentially risky third-party SDK detected in sensitive app |

### 🔓 API Keys & Secrets Detection (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `API_KEY_EXPOSED` | HIGH | Detects 27+ types of API keys: Firebase, AWS, Stripe, GitHub, Slack, Twilio, SendGrid, etc. |
| `ENV_FILE_COMMITTED` | HIGH | Environment file with secrets potentially committed to repository |

### 🐛 Debug & Production Security (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `TEST_CREDENTIALS_IN_CODE` | MEDIUM | Test credentials or example passwords found in source code |
| `DEBUG_ENDPOINTS_EXPOSED` | HIGH | Debug or development endpoints exposed in production code |
| `REDUX_DEVTOOLS_ENABLED` | MEDIUM | Redux DevTools enabled without production check |

### 🤖 Android Security (8 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `ANDROID_CLEARTEXT_ENABLED` | HIGH | android:usesCleartextTraffic="true" in manifest |
| `ANDROID_DEBUGGABLE_ENABLED` | HIGH | android:debuggable="true" in production manifest |
| `ANDROID_BACKUP_ALLOWED` | MEDIUM | android:allowBackup="true" for sensitive app |
| `ANDROID_EXPORTED_COMPONENT` | HIGH | Exported Android component without permission protection |
| `ANDROID_INTENT_FILTER_PERMISSIVE` | MEDIUM | Overly permissive intent filter may expose functionality |
| `ANDROID_UNPROTECTED_RECEIVER` | HIGH | Broadcast receiver without permission protection |
| `ANDROID_CONTENT_PROVIDER_NO_PERMISSION` | HIGH | Content provider without read/write permissions |
| `INSECURE_KEYSTORE_USAGE` | HIGH | Android Keystore used without proper security (ECB mode, no user auth, no StrongBox) |
| `EXCESSIVE_PERMISSIONS` | LOW | Android permissions declared but potentially not used in code |

### 🍎 iOS Security (8 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `IOS_ATS_DISABLED` | HIGH | App Transport Security (ATS) disabled (NSAllowsArbitraryLoads) |
| `IOS_USAGE_DESCRIPTIONS_MISSING` | MEDIUM | Missing iOS usage description for privacy-sensitive permission |
| `IOS_BACKGROUND_MODES_UNNECESSARY` | MEDIUM | Potentially unnecessary background modes enabled |
| `IOS_UNIVERSAL_LINKS_MISCONFIGURED` | MEDIUM | Universal links configured without proper validation |
| `IOS_CUSTOM_URL_SCHEME_UNPROTECTED` | MEDIUM | Custom URL scheme without validation code |
| `IOS_KEYCHAIN_ACCESS_GROUP_INSECURE` | MEDIUM | Keychain access group configuration may expose data |
| `IOS_DATA_PROTECTION_MISSING` | LOW | Data protection entitlement not configured for sensitive app |
| `IOS_ATS_EXCEPTION_TOO_PERMISSIVE` | HIGH | App Transport Security exception too permissive |
| `INSECURE_KEYCHAIN_USAGE` | HIGH | iOS Keychain used without proper accessibility and protection (kSecAttrAccessibleAlways, missing access control) |
| `IOS_KEYCHAIN_ACCESS_GROUP_INSECURE` | MEDIUM | Keychain access group configuration may expose data |
| `IOS_DATA_PROTECTION_MISSING` | LOW | Data protection entitlement not configured for sensitive app |
| `IOS_ATS_EXCEPTION_TOO_PERMISSIVE` | HIGH | App Transport Security exception too permissive |

### ⚙️ Configuration (1 rule)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `EXPO_INSECURE_PERMISSIONS` | LOW | Flags potentially dangerous permissions in app.json |

</details>

### 🔍 API Key Detection

The `API_KEY_EXPOSED` rule detects 27+ types of exposed secrets:

**Cloud Providers**: Firebase, AWS (Access Keys, Secrets), Google Cloud, Heroku, DigitalOcean  
**Payment**: Stripe (Live, Restricted, Publishable), PayPal  
**Communication**: Twilio, SendGrid, Mailgun, Mailchimp, Slack  
**Development**: GitHub (PAT, OAuth), GitLab  
**Cryptographic**: Private Keys (RSA, SSH, PGP), Certificates  
**Authentication**: JWT, Bearer Tokens, Basic Auth, OAuth Client Secrets

## Examples

Test the scanner with included sample projects:

```bash
# Scan vulnerable app (35+ security issues)
rnsec scan --path examples/vulnerable-app

# Scan secure app (minimal issues)
rnsec scan --path examples/secure-app

# Scan and open HTML report
rnsec scan --path examples/vulnerable-app
open rnsec-report.html  # macOS
# or
start rnsec-report.html  # Windows
# or
xdg-open rnsec-report.html  # Linux
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g rnsec
      - run: rnsec scan --output security-results.json --silent
      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: |
            security-results.json
            rnsec-report.html
```

### Exit Codes

- `0` - No high-severity issues (passes CI/CD)
- `1` - High-severity vulnerabilities detected (fails CI/CD)

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-rule`
3. Make your changes and test with examples
4. Commit: `git commit -m 'Add new security rule'`
5. Push: `git push origin feature/new-rule`
6. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/rnsec.git
cd rnsec
npm install
npm run build
```

### Adding New Security Rules

1. Create or modify a scanner in `src/scanners/`
2. Follow the `Rule` interface pattern
3. Test with `examples/vulnerable-app`
4. Update README with rule details

### Project Structure

```
src/
├── cli/              # Command-line interface
├── core/             # Scanning engine (AST parser, file walker, rule engine)
├── scanners/         # 13 security scanners with 62 rules
├── types/            # TypeScript definitions
└── utils/            # Helper functions
```

## License

MIT License - see [LICENSE](LICENSE) for details

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/rnsec/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/rnsec/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/yourusername/rnsec/wiki)

---

<p align="center">
  Built with ❤️ for the React Native community
</p>
