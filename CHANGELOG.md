# Changelog

All notable changes to rnsec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 🎯 **63 comprehensive security rules** covering:
  - Storage security (6 rules)
  - Network security (13 rules)
  - Authentication & authorization (6 rules)
  - Cryptography (2 rules)
  - Logging (2 rules)
  - React Native specific (10 rules)
  - API keys & secrets (2 rules)
  - Debug & production security (3 rules)
  - Android platform (8 rules)
  - iOS platform (8 rules)
  - Configuration (1 rule)
  - Manifest files (2 rules)

- 🔍 **Smart detection features**:
  - Automatic filtering of debug/development context
  - Context-aware rule evaluation
  - False positive reduction
  - 27+ API key patterns detection

- 📊 **Rich reporting**:
  - Interactive HTML reports with syntax highlighting
  - JSON output for CI/CD integration
  - Terminal output with color coding
  - Detailed findings with line numbers and code snippets

- 🚀 **CLI features**:
  - Simple `rnsec scan` command
  - `rnsec rules` to list all rules
  - Progress indicators during scan
  - Configurable output formats

- 🎨 **User experience**:
  - Beautiful terminal output with chalk
  - Spinner animations during scanning
  - Risk level assessment (Critical/High/Medium/Low)
  - Scan performance metrics

### Security Rules Highlights

**HIGH severity** rules for critical vulnerabilities:
- Hardcoded API keys and secrets (27+ patterns)
- Insecure HTTP URLs
- Weak cryptography (MD5, SHA1)
- Eval() usage
- Android debuggable in production
- iOS ATS disabled
- Certificate pinning disabled
- And more...

**MEDIUM severity** rules for important issues:
- Sensitive data in AsyncStorage
- Missing SSL/TLS configuration
- Weak TLS versions
- No request timeouts
- Biometric fallback issues
- And more...

**LOW severity** rules for improvements:
- Missing security headers
- Excessive permissions
- Third-party SDK risks
- Code hygiene issues

### Technical Features

- ✅ TypeScript-first architecture
- ✅ AST-based analysis using Babel
- ✅ Zero external API calls (fully local)
- ✅ Fast scanning (< 100ms for most projects)
- ✅ Extensible rule engine
- ✅ XML/Plist/JSON/JS/TS support
- ✅ Monorepo friendly

### Developer Experience

- 📦 Simple installation: `npm install -g rnsec`
- 🎯 Zero configuration required
- 📝 Comprehensive documentation
- 🔧 TypeScript types included
- 🎨 Syntax-highlighted code snippets in reports

## [1.0.0] - 2024-12-18

### 🎉 Initial Release

The first public release of **rnsec** - React Native Security Scanner!

#### Core Features
- Complete static analysis engine
- 63 security rules across 13 categories
- HTML and JSON report generation
- CLI with scan and rules commands
- Support for React Native, Expo, and native mobile projects

#### Platform Support
- ✅ macOS
- ✅ Linux  
- ✅ Windows
- Node.js 18+ required

#### File Types Analyzed
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Android Manifests (.xml)
- iOS Plists (.plist)
- Configuration files (.json)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute to rnsec.

## Questions?

- 📫 Email: adnanpoviolabs@gmail.com
- 🐛 Issues: https://github.com/adnxy/rnsec/issues
- ⭐ Star us: https://github.com/adnxy/rnsec

