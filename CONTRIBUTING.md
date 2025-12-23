# Contributing to rnsec

First off, thank you for considering contributing to rnsec! It's people like you that make rnsec such a great tool for the React Native security community.

## 🎯 Ways to Contribute

- 🐛 **Report bugs** - Found a false positive? Let us know!
- 💡 **Suggest features** - Have an idea for a new security rule?
- 📝 **Improve documentation** - Help others understand rnsec better
- 🔧 **Submit PRs** - Fix bugs or add new features
- ⭐ **Star the repo** - Show your support!

## 🚀 Getting Started

### Prerequisites

- Node.js 18+ and npm
- Git
- TypeScript knowledge

### Setup Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/rnsec.git
cd rnsec

# Install dependencies
npm install

# Build the project
npm run build

# Test it out
node dist/cli/index.js scan examples/vulnerable-app
```

## 📝 Pull Request Process

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our code style
3. **Add tests** if you're adding functionality
4. **Update documentation** if needed
5. **Ensure the build passes**: `npm run build`
6. **Test your changes** thoroughly
7. **Submit a PR** with a clear description

### PR Title Format

Use conventional commits:
```
feat: Add new RULE_NAME scanner for XYZ
fix: Correct false positive in STORAGE_SCANNER
docs: Update README with new examples
test: Add tests for authentication scanner
```

## 🔍 Adding a New Security Rule

Want to add a new security rule? Here's the template:

```typescript
// src/scanners/yourScanner.ts
const yourNewRule: Rule = {
  id: 'YOUR_RULE_ID',
  description: 'Clear description of the security issue',
  severity: Severity.HIGH, // or MEDIUM, LOW
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    // Your detection logic here
    
    return findings;
  },
};
```

### Rule Guidelines

- **Be specific**: Clearly identify the security issue
- **Avoid false positives**: Check for debug contexts, test files
- **Provide context**: Include line numbers and code snippets
- **Offer solutions**: Give actionable suggestions
- **Performance matters**: Optimize for speed when scanning large codebases

## 🧪 Testing

We need tests! Currently, rnsec doesn't have comprehensive test coverage. If you're interested in helping:

```bash
# Run tests (when available)
npm test

# Run with coverage
npm run test:coverage
```

## 📖 Documentation

- Update the README if you add user-facing features
- Add JSDoc comments to public APIs
- Update rule documentation in the README

## 🐛 Reporting Bugs

**Great Bug Reports** include:

- Quick summary of the issue
- Steps to reproduce (with code samples)
- What you expected to happen
- What actually happened
- Your environment (Node version, OS, etc.)
- Screenshots if applicable

Use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)

## 💡 Suggesting Features

**Great Feature Requests** include:

- Clear use case and problem statement
- Proposed solution
- Alternative solutions considered
- Examples of similar features in other tools
- Willingness to contribute the implementation

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what's best for the community

**Unacceptable behavior:**
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## 🎓 Development Tips

### Project Structure
```
rnsec/
├── src/
│   ├── cli/           # Command-line interface
│   ├── core/          # Core engine and reporters
│   ├── scanners/      # Security rule scanners
│   ├── types/         # TypeScript type definitions
│   └── utils/         # Utility functions
├── examples/          # Test applications
└── dist/              # Compiled JavaScript (generated)
```

### Common Tasks

```bash
# Watch mode for development
npm run build -- --watch

# Format code (when Prettier is added)
npm run format

# Lint code (when ESLint is added)
npm run lint
```

## 🏆 Recognition

Contributors will be recognized in:
- README.md Contributors section
- Release notes
- Our hearts ❤️

## 📞 Questions?

- Open an issue with the "question" label
- Join our discussions
- Email: adnanpoviolabs@gmail.com

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making rnsec better! 🙏**

