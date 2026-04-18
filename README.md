# Powertrain CVE Analyzer for Burp Suite

<p align="center">
  <img src="https://img.shields.io/badge/Burp%20Suite-Extension-orange" alt="Burp Suite Extension">
  <img src="https://img.shields.io/badge/Language-Python-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Active">
</p>

A professional Burp Suite extension that integrates **Oxytis Powertrain CVE intelligence** directly into your security testing workflow. Get comprehensive vulnerability analysis, risk scoring, and actionable remediation guidance without leaving Burp Suite.

## 🚀 Features

- **🔍 Real-time CVE Analysis** - Instant access to detailed vulnerability intelligence
- **📊 Advanced Risk Scoring** - CVSS scores with Oxytis risk assessment
- **🧠 SOO Model Analysis** - Patent-pending Subject-Object-Opportunity framework
- **🛡️ HEXAD Security Primitives** - Comprehensive impact analysis across six security domains
- **📋 OWASP Top 10 Mapping** - Automatic categorization to current OWASP standards
- **🖱️ Context Menu Integration** - Right-click CVE IDs anywhere in Burp to analyze
- **📄 Professional Reports** - Clean, formatted output perfect for security assessments
- **⚡ Background Processing** - Non-blocking API calls keep Burp responsive

## 📸 Screenshots

### Main Interface
![Main Interface](screenshots/main-interface.png)

### CVE Analysis Output
![CVE Analysis](screenshots/cve-analysis.png)

### Context Menu Integration
![Context Menu](screenshots/context-menu.png)

## 🛠️ Installation

### Prerequisites
- Burp Suite Professional or Community Edition
- Python support enabled in Burp (Jython)
- Active internet connection for API access

### Step-by-Step Installation

1. **Download the Extension**
   ```bash
   git clone https://github.com/yourusername/powertrain-burp-extension.git
   cd powertrain-burp-extension
   ```

2. **Load in Burp Suite**
   - Open Burp Suite
   - Navigate to **Extender** → **Extensions**
   - Click **Add**
   - Select **Python** as the extension type
   - Choose `powertrain_cve_analyzer.py`
   - Click **Next** to load

3. **Configure API Access**
   - Go to the new **Powertrain CVE** tab
   - Enter your Oxytis API token
   - Click **Test API Connection** to verify

## ⚙️ Configuration

### Getting Your API Token
1. Contact Oxytis to obtain API access
2. Your token will be provided for integration use
3. Enter the token in the extension configuration

### API Settings
- **API URL**: `https://oxytis.com/api/cve/analyze` (default)
- **Token**: Your provided API key
- **Format**: JSON or PDF output

## 🎯 Usage

### Method 1: Direct CVE Analysis
1. Navigate to the **Powertrain CVE** tab
2. Enter a CVE ID (e.g., `CVE-2024-1234`)
3. Select output format
4. Click **Analyze CVE**
5. View comprehensive analysis results

### Method 2: Context Menu Analysis
1. Select any CVE ID text in requests/responses
2. Right-click and choose **Analyze with Powertrain**
3. Analysis runs automatically in the CVE tab

### Method 3: Security Testing Workflow
- **Discovery Phase**: Analyze CVEs found in version banners
- **Exploitation Phase**: Research vulnerability details before testing
- **Reporting Phase**: Include detailed CVE intelligence in findings

## 📊 Analysis Output

The extension provides comprehensive vulnerability intelligence:

### Risk Assessment
- **CVSS Score & Vector**: Industry-standard vulnerability scoring
- **Oxytis Risk Score**: Enhanced risk assessment with contextual factors
- **Residual Risk**: Post-mitigation risk estimation
- **OWASP Category**: Automatic mapping to OWASP Top 10 2025

### Technical Analysis
- **SOO Model Breakdown**: Subject-Object-Opportunity analysis (Patent Pending)
- **Attack Scenarios**: Realistic exploitation examples
- **HEXAD Security Impact**: Six-dimensional security primitive analysis
  - Confidentiality, Integrity, Availability
  - Possession, Authenticity, Utility

### Actionable Intelligence
- **Remediation Recommendations**: Specific mitigation guidance
- **Technical Details**: CWE mappings and vulnerability mechanics
- **Business Impact**: Risk communication for stakeholders

## 🔧 Integration Examples

### Penetration Testing
```
1. Discover services with version banners
2. Right-click CVE references in Burp
3. Get instant vulnerability intelligence
4. Prioritize testing based on risk scores
5. Include detailed analysis in reports
```

### Vulnerability Assessment
```
1. Import scanner results into Burp
2. Analyze CVEs with contextual intelligence
3. Use Oxytis risk scores for prioritization
4. Generate detailed client communications
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with Burp Suite
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏢 About Oxytis

[Oxytis](https://oxytis.com) provides advanced cybersecurity intelligence and forensic analysis services. The Powertrain CVE analysis system delivers enterprise-grade vulnerability intelligence with patent-pending methodologies.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/powertrain-burp-extension/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/powertrain-burp-extension/wiki)
- **API Support**: Contact Oxytis for API access and support

## 🔄 Changelog

### v1.0.0 (2026-04-18)
- Initial release
- Full CVE analysis integration
- SOO model support
- HEXAD primitive analysis
- Context menu integration
- Professional output formatting

---

<p align="center">
  <strong>Transform your security testing workflow with professional CVE intelligence.</strong>
</p>

<p align="center">
  Made with ❤️ for the security community
</p>
