# Installation Guide

This guide will walk you through installing the Powertrain CVE Analyzer extension in Burp Suite.

## Prerequisites

- **Burp Suite**: Professional or Community Edition
- **Python Support**: Jython must be configured in Burp
- **Internet Access**: Required for API connectivity
- **API Token**: Contact Oxytis for access credentials

## Step 1: Download the Extension

### Option A: Download from GitHub Releases
1. Go to the [Releases page](https://github.com/oxytis/powertrain-burp-extension/releases)
2. Download the latest `powertrain_cve_analyzer.py` file

### Option B: Clone the Repository
```bash
git clone https://github.com/yourusername/powertrain-burp-extension.git
cd powertrain-burp-extension
```

## Step 2: Configure Burp Suite Python Support

1. Open Burp Suite
2. Go to **Extender** → **Options**
3. In the **Python Environment** section:
   - Set the location of your Python/Jython installation
   - Ensure the status shows "Python environment is working"

## Step 3: Load the Extension

1. In Burp Suite, navigate to **Extender** → **Extensions**
2. Click **Add** to add a new extension
3. In the **Extension Details** dialog:
   - **Extension Type**: Select "Python"
   - **Extension File**: Browse and select `powertrain_cve_analyzer.py`
4. Click **Next** to load the extension
5. Check the **Output** and **Errors** tabs for any loading issues

## Step 4: Configure API Access

1. Look for the new **Powertrain CVE** tab in Burp Suite
2. In the **API Configuration** section:
   - **API URL**: Should be pre-filled with `https://oxytis.com/api/cve/analyze`
   - **API Token**: Enter your Oxytis-provided token
3. Click **Test API Connection** to verify connectivity
4. You should see a "API connection successful!" message

## Step 5: Test the Extension

1. In the **Powertrain CVE** tab, enter a test CVE ID: `CVE-2024-1234`
2. Select **JSON** format
3. Click **Analyze CVE**
4. You should see detailed analysis results in the results panel

## Troubleshooting

### Extension Won't Load
- **Check Python Environment**: Ensure Jython is properly configured
- **File Permissions**: Make sure Burp can read the extension file
- **Check Errors Tab**: Look for specific error messages

### API Connection Issues
- **Network Connectivity**: Ensure you can reach oxytis.com
- **Token Validation**: Verify your API token is correct
- **Firewall/Proxy**: Check if corporate firewalls are blocking the connection

### No Context Menu Options
- **Extension Loading**: Ensure the extension loaded without errors
- **CVE Format**: Right-click only works on properly formatted CVE IDs (CVE-YYYY-NNNN)
- **Text Selection**: Make sure you've selected the CVE text before right-clicking

### Unicode/Encoding Errors
- **Burp Version**: Ensure you're using a recent version of Burp Suite
- **Python Version**: Some older Jython versions have Unicode issues

## Getting API Access

1. **Contact Oxytis**: Reach out through their website
2. **Specify Use Case**: Mention Burp Suite integration
3. **Receive Credentials**: API token will be provided
4. **Test Access**: Use the extension's connection test feature

## Next Steps

Once installed and configured:
1. **Integrate into Workflow**: Use during penetration testing
2. **Explore Features**: Try both direct analysis and context menu
3. **Customize Settings**: Adjust output preferences
4. **Provide Feedback**: Report issues or suggest improvements

## Support

If you encounter issues:
1. **Check Documentation**: Review the troubleshooting section
2. **Search Issues**: Look for similar problems on GitHub
3. **Create Issue**: File a detailed bug report if needed
4. **Community Support**: Ask questions in GitHub Discussions

---

**Happy Security Testing!** 🛡️
