# Installation Guide

This guide walks you through installing the **Powertrain** extension in Burp Suite.

## Prerequisites

- **Burp Suite**: Professional or Community Edition
- **Python Support**: Jython must be configured in Burp
- **Internet Access**: Required for API connectivity
- **API Token**: Contact Oxytis for access credentials

## Step 1: Download the Extension

### Option A: Download from GitHub Releases
1. Go to the [Releases page](https://github.com/oxytis/powertrain-burp-extension/releases)
2. Download the latest `powertrain_burp_extension.py` file

### Option B: Clone the Repository
```bash
git clone https://github.com/oxytis/powertrain-burp-extension.git
cd powertrain-burp-extension
```

## Step 2: Configure Burp Suite Python Support

1. Open Burp Suite
2. Go to **Settings** → **Extensions** (older Burp: **Extender** → **Options**)
3. In the **Python environment** section:
   - Set the location of your Jython standalone JAR
   - Ensure the status shows the Python environment is working

## Step 3: Load the Extension

1. In Burp Suite, navigate to **Extensions** → **Installed**
2. Click **Add** to add a new extension
3. In the **Extension Details** dialog:
   - **Extension Type**: Select "Python"
   - **Extension File**: Browse and select `powertrain_burp_extension.py`
4. Click **Next** to load the extension
5. Check the **Output** and **Errors** tabs for any loading issues

## Step 4: Configure API Access

1. Look for the new **Powertrain** tab in Burp Suite
2. In the API configuration section:
   - **CVE Endpoint**: pre-filled with `https://oxytis.com/api/cve/analyze`
   - **API Token**: enter your Oxytis-provided token
3. Click **Test API Connection** to verify connectivity

## Step 5: Review Privacy Settings (finding assessment)

Finding assessment sends evidence from a Burp issue to the Powertrain API. Before
using it against client systems, check the **Evidence sent** control in the
Powertrain tab:

- **Redacted** (default) — shape-only view of the request/response; no hostname,
  bodies, cookie or credential values leave Burp.
- **Metadata-only** — as Redacted, without highlighted snippets.
- **Raw** — unmodified first request/response; opt-in, not for client systems
  without consent.

Leave **Preview payload before sending** on to see exactly what will be sent
before it leaves Burp. See the README's Privacy & Data Handling section for the
full list of what each mode transmits.

## Step 6: Test the Extension

1. In the **Powertrain** tab, enter a test CVE ID: `CVE-2024-1234`
2. Click **Analyze CVE**
3. You should see detailed analysis results in the results panel
4. To test finding mode, right-click a Burp Scanner issue and choose
   **Assess with Tally (estimate CVSS)** — the payload preview should appear
   before anything is sent.

## Troubleshooting

### Extension Won't Load
- **Check Python Environment**: Ensure Jython is properly configured
- **File Permissions**: Make sure Burp can read the extension file
- **Check Errors Tab**: Look for specific error messages

### API Connection Issues
- **Network Connectivity**: Ensure you can reach oxytis.com
- **Token Validation**: Verify your API token is correct
- **Firewall/Proxy**: Check whether corporate firewalls are blocking the connection

### No Context Menu Options
- **Extension Loading**: Ensure the extension loaded without errors
- **CVE Format**: CVE right-click only works on properly formatted CVE IDs (CVE-YYYY-NNNN)
- **Finding Assessment**: For no-CVE findings, right-click a Scanner issue rather than selected text

### Payload Preview Shows Unexpected Data
- Switch **Evidence sent** to **Metadata-only** to send no snippets at all
- Confirm you are not in **Raw** mode when testing against systems you don't own

### Unicode/Encoding Errors
- **Burp Version**: Ensure you're using a recent version of Burp Suite
- **Python Version**: Some older Jython versions have Unicode issues

## Getting API Access

1. **Contact Oxytis**: Reach out through their website
2. **Specify Use Case**: Mention Burp Suite integration
3. **Receive Credentials**: An API token will be provided

## Support

If you encounter issues:
1. **Check Documentation**: Review the troubleshooting section and README
2. **Search Issues**: Look for similar problems on GitHub
3. **Create Issue**: File a detailed bug report if needed

---

**Happy Security Testing!**
