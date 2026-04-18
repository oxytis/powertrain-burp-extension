# Contributing to Powertrain CVE Analyzer

Thank you for considering contributing to the Powertrain CVE Analyzer for Burp Suite! This document outlines how to contribute to the project.

## 🚀 Getting Started

### Prerequisites
- Burp Suite Professional or Community Edition
- Python knowledge (Jython environment)
- Understanding of CVE analysis and security testing workflows

### Development Environment Setup
1. Fork the repository
2. Clone your fork locally
3. Load the extension in Burp Suite for testing
4. Make your changes
5. Test thoroughly with various CVE inputs

## 🛠️ Development Guidelines

### Code Style
- Follow PEP 8 Python style guidelines
- Use descriptive variable names
- Add comments for complex logic
- Maintain the existing code structure

### Key Components
- **UI Components**: Swing-based interface elements
- **API Integration**: HTTP requests to Powertrain API
- **Text Processing**: CVE analysis result formatting
- **Error Handling**: Graceful degradation for API failures

### Testing
- Test with various CVE IDs
- Verify Unicode handling
- Test API connection failures
- Check context menu functionality

## 📋 How to Contribute

### Bug Reports
When filing an issue, please include:
- Burp Suite version
- Extension version
- Steps to reproduce
- Expected vs actual behavior
- Any error messages

### Feature Requests
- Describe the feature clearly
- Explain the use case
- Consider implementation complexity
- Check if it aligns with the extension's goals

### Code Contributions
1. **Fork & Branch**: Create a feature branch from `main`
2. **Implement**: Make your changes with clear commit messages
3. **Test**: Thoroughly test your changes
4. **Document**: Update documentation if needed
5. **Submit**: Create a pull request with a clear description

### Pull Request Process
1. Ensure your code follows the style guidelines
2. Test the extension thoroughly
3. Update documentation if you're adding features
4. Write a clear PR description explaining:
   - What you changed
   - Why you changed it
   - How to test it

## 🔍 Areas for Contribution

### High Priority
- Additional output formats
- Enhanced error handling
- Performance optimizations
- UI/UX improvements

### Medium Priority
- Additional API integrations
- Extended CVE data parsing
- Custom report templates
- Keyboard shortcuts

### Low Priority
- Code refactoring
- Documentation improvements
- Additional test cases

## 🐛 Reporting Security Issues

If you discover a security vulnerability, please:
1. **DO NOT** file a public issue
2. Email security details privately
3. Include steps to reproduce
4. Allow time for investigation before disclosure

## 📚 Resources

- [Burp Suite Extension Development](https://portswigger.net/burp/extender)
- [Python in Burp (Jython)](https://jython.org/)
- [Oxytis Powertrain API Documentation](https://oxytis.com/api)

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and community support
- **Documentation**: Check the wiki for detailed guides

## 🎯 Contribution Ideas

### Beginner Friendly
- Fix typos in documentation
- Improve error messages
- Add input validation
- Enhance tooltips and help text

### Intermediate
- Add new output formatting options
- Implement caching for API responses
- Create keyboard shortcuts
- Improve Unicode handling

### Advanced
- Integrate with other security APIs
- Add batch CVE analysis
- Implement custom risk scoring
- Create automated testing framework

## 📋 Code Review Process

All contributions go through code review:
1. **Automated Checks**: Basic code quality
2. **Functionality Review**: Feature works as intended
3. **Security Review**: No security implications
4. **Documentation Review**: Changes are documented
5. **Integration Review**: Fits with existing codebase

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- Special mention for major features

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Powertrain CVE Analyzer better for the security community! 🙏
