#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Oxytis Powertrain Extension for Burp Suite
Integrates Oxytis Powertrain vulnerability intelligence into Burp Suite:
CVE lookup and AI-assisted assessment of Scanner findings without a CVE.
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JLabel, JTextField, JButton, JTextArea, 
                        JScrollPane, BoxLayout, JMenuItem, JOptionPane,
                        BorderFactory, SwingConstants, JComboBox, JCheckBox)
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, FlowLayout, Dimension, Color, Font
from java.awt.event import ActionListener
from javax.swing.border import EmptyBorder
from java.util import Date
import json
import urllib2
import threading
import re

# Burp Scanner issue name -> CWE (first substring match wins; None -> let the model infer)
_ISSUE_CWE = [
    ("cross-site scripting",            "CWE-79"),
    ("sql injection",                   "CWE-89"),
    ("os command injection",            "CWE-78"),
    ("command injection",               "CWE-78"),
    ("cross-site request forgery",      "CWE-352"),
    ("csrf",                            "CWE-352"),
    ("server-side request forgery",     "CWE-918"),
    ("ssrf",                            "CWE-918"),
    ("path traversal",                  "CWE-22"),
    ("directory traversal",             "CWE-22"),
    ("xml external entity",             "CWE-611"),
    ("xxe",                             "CWE-611"),
    ("server-side template injection",  "CWE-1336"),
    ("template injection",              "CWE-1336"),
    ("open redirect",                   "CWE-601"),
    ("ldap injection",                  "CWE-90"),
    ("xpath injection",                 "CWE-643"),
    ("response header injection",       "CWE-113"),
    ("header injection",                "CWE-113"),
    ("cleartext",                       "CWE-319"),
    ("deserialization",                 "CWE-502"),
    ("clickjacking",                    "CWE-1021"),
    ("cross-origin resource sharing",   "CWE-942"),
    ("session token in url",            "CWE-598"),
    ("xml injection",                   "CWE-91"),
]

# Finding-assessment privacy modes (what leaves Burp). "Raw" is the pre-1.1 behaviour.
_PRIVACY_MODES = ["Redacted", "Metadata-only", "Raw"]

# Response headers whose *values* are security-relevant and never carry client data.
# Every other header is sent as name only.
_HEADER_VALUE_ALLOW = set([
    "content-type", "content-length", "server", "x-powered-by",
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "content-security-policy", "content-security-policy-report-only",
    "referrer-policy", "permissions-policy", "cache-control", "pragma",
    "access-control-allow-origin", "access-control-allow-credentials",
    "x-xss-protection", "cross-origin-opener-policy", "cross-origin-resource-policy",
])
_SENSITIVE_KEY_NAMES = (r"pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth|session|sid|jsessionid|"
                        r"phpsessid|csrf|xsrf|nonce|otp|ssn|email|user(?:name)?|login|account|card|cvv|iban")
# key=value / key: value / "key":"value" -> keep the key, drop the value
_SENSITIVE_KV = re.compile(r'(?i)(["\']?\b(?:' + _SENSITIVE_KEY_NAMES + r')\b["\']?\s*[:=]\s*["\']?)([^"\'&;\s,]+)')
# Leading lines of a prior Tally/Powertrain assessment pasted into an issue; stripped before
# re-assessment so the old vector never anchors the new one.
_PRIOR_ASSESSMENT = re.compile(r"(?im)^(CVSS v4\.0:|OWASP Category:|CWE-\d+:).*$\n?")
_MAX_SNIPPET = 300      # chars per Burp-highlighted evidence snippet
_MAX_SNIPPETS = 4

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, ActionListener):
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension with persistent settings"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Oxytis Powertrain")
        
        # Load saved settings
        self._load_settings()
        
        # Initialize UI
        self._init_ui()
        
        # Register as HTTP listener and context menu factory
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        # Add custom tab
        callbacks.addSuiteTab(self)
        
        print("[+] Oxytis Powertrain loaded successfully")
        print("[+] Configure API settings in the Powertrain tab")
    
    def _load_settings(self):
        """Load saved settings from Burp's extension settings"""
        try:
            # Load API URL
            saved_url = self._callbacks.loadExtensionSetting("api_url")
            self._saved_api_url = saved_url if saved_url else "https://oxytis.com/api/cve/analyze"
            
            # Load API Token
            saved_token = self._callbacks.loadExtensionSetting("api_token")
            self._saved_api_token = saved_token if saved_token else ""

            # Privacy: what leaves Burp on a finding assessment
            saved_priv = self._callbacks.loadExtensionSetting("privacy_mode")
            self._saved_privacy_mode = saved_priv if saved_priv in _PRIVACY_MODES else "Redacted"
            self._saved_preview = self._callbacks.loadExtensionSetting("preview_payload") != "0"
            
            print("[+] Settings loaded from Burp configuration")
        except Exception as e:
            print("[-] Error loading settings: " + str(e))
            self._saved_api_url = "https://oxytis.com/api/cve/analyze"
            self._saved_api_token = ""
            self._saved_privacy_mode = "Redacted"
            self._saved_preview = True
    
    def _save_settings(self):
        """Save current settings to Burp's extension settings"""
        try:
            # Save API URL
            api_url = self._api_url_field.getText()
            self._callbacks.saveExtensionSetting("api_url", api_url)
            
            # Save API Token
            api_token = self._api_token_field.getText()
            self._callbacks.saveExtensionSetting("api_token", api_token)

            self._callbacks.saveExtensionSetting("privacy_mode",
                str(self._privacy_combo.getSelectedItem()))
            self._callbacks.saveExtensionSetting("preview_payload",
                "1" if self._preview_check.isSelected() else "0")
            
            print("[+] Settings saved to Burp configuration")
        except Exception as e:
            print("[-] Error saving settings: " + str(e))
    
    def _init_ui(self):
        """Initialize the user interface"""
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Header
        header_panel = self._create_header_panel()
        self._main_panel.add(header_panel, BorderLayout.NORTH)
        
        # Configuration panel
        config_panel = self._create_config_panel()
        self._main_panel.add(config_panel, BorderLayout.CENTER)
        
        # Results panel
        results_panel = self._create_results_panel()
        self._main_panel.add(results_panel, BorderLayout.SOUTH)
    
    def _create_header_panel(self):
        """Create the header panel"""
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_panel.setBorder(BorderFactory.createTitledBorder("Oxytis Powertrain"))
        
        title_label = JLabel("Oxytis Powertrain")
        title_label.setFont(Font("Arial", Font.BOLD, 16))
        header_panel.add(title_label)
        
        return header_panel
    
    def _create_config_panel(self):
        """Create the configuration panel with persistent settings"""
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(BorderFactory.createTitledBorder("API Configuration"))
        
        # API URL
        url_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        url_panel.add(JLabel("API URL:"))
        self._api_url_field = JTextField(self._saved_api_url, 30)
        # Add change listener to auto-save
        self._api_url_field.getDocument().addDocumentListener(SettingsChangeListener(self))
        url_panel.add(self._api_url_field)
        config_panel.add(url_panel)
        
        # API Token
        token_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        token_panel.add(JLabel("API Token:"))
        self._api_token_field = JTextField(self._saved_api_token, 30)
        # Add change listener to auto-save
        self._api_token_field.getDocument().addDocumentListener(SettingsChangeListener(self))
        token_panel.add(self._api_token_field)
        config_panel.add(token_panel)
        
        # Settings info
        info_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        info_label = JLabel("Settings are automatically saved and will persist across Burp restarts")
        info_label.setFont(Font("Arial", Font.ITALIC, 10))
        info_panel.add(info_label)
        config_panel.add(info_panel)
        
        # CVE Input
        cve_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        cve_panel.add(JLabel("CVE ID:"))
        self._cve_input_field = JTextField("CVE-", 20)
        cve_panel.add(self._cve_input_field)
        
        # Analyze button
        self._analyze_button = JButton("Analyze CVE")
        self._analyze_button.addActionListener(self)
        cve_panel.add(self._analyze_button)
        
        config_panel.add(cve_panel)
        
        # Finding assessment options (used by right-click "Assess with Tally")
        finding_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        finding_panel.add(JLabel("Finding exposure:"))
        self._exposure_combo = JComboBox(["External", "Internal", "Unknown"])
        finding_panel.add(self._exposure_combo)
        finding_panel.add(JLabel("   Controls:"))
        self._controls_combo = JComboBox(["Partial", "Ineffective", "Effective"])
        finding_panel.add(self._controls_combo)
        config_panel.add(finding_panel)

        # Privacy controls: what evidence is sent to the Powertrain API
        privacy_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        privacy_panel.add(JLabel("Evidence sent:"))
        self._privacy_combo = JComboBox(_PRIVACY_MODES)
        self._privacy_combo.setSelectedItem(self._saved_privacy_mode)
        self._privacy_combo.addActionListener(self)
        privacy_panel.add(self._privacy_combo)
        self._preview_check = JCheckBox("Preview payload before sending", self._saved_preview)
        self._preview_check.addActionListener(self)
        privacy_panel.add(self._preview_check)
        config_panel.add(privacy_panel)
        privacy_info = JPanel(FlowLayout(FlowLayout.LEFT))
        privacy_label = JLabel("Redacted: request/response shape + Burp-highlighted snippets with values masked. "
                               "Metadata-only: shape only, no snippets. Raw: unmodified (not for client data).")
        privacy_label.setFont(Font("Arial", Font.ITALIC, 10))
        privacy_info.add(privacy_label)
        config_panel.add(privacy_info)
        
        # Test connection button
        test_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._test_button = JButton("Test API Connection")
        self._test_button.addActionListener(self)
        test_panel.add(self._test_button)
        
        # Clear settings button
        clear_button = JButton("Clear Saved Settings")
        clear_button.addActionListener(self)
        test_panel.add(clear_button)
        
        config_panel.add(test_panel)
        
        return config_panel
    
    def _create_results_panel(self):
        """Create the results display panel"""
        results_panel = JPanel(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("Analysis Results"))
        
        self._results_area = JTextArea(20, 80)
        self._results_area.setEditable(False)
        self._results_area.setFont(Font("Consolas", Font.PLAIN, 12))
        
        scroll_pane = JScrollPane(self._results_area)
        results_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Clear button
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        clear_button = JButton("Clear Results")
        clear_button.addActionListener(self)
        button_panel.add(clear_button)
        results_panel.add(button_panel, BorderLayout.SOUTH)
        
        return results_panel
    
    def actionPerformed(self, event):
        """Handle button clicks with settings management"""
        command = event.getActionCommand()
        
        if command == "Test API Connection":
            self._test_api_connection()
        elif command == "Analyze CVE":
            self._analyze_cve()
        elif command == "Clear Results":
            self._results_area.setText("")
        elif command == "Clear Saved Settings":
            self._clear_settings()
        elif event.getSource() in (self._privacy_combo, self._preview_check):
            self._save_settings()
    
    def _clear_settings(self):
        """Clear all saved settings"""
        try:
            self._callbacks.saveExtensionSetting("api_url", None)
            self._callbacks.saveExtensionSetting("api_token", None)
            self._callbacks.saveExtensionSetting("privacy_mode", None)
            self._callbacks.saveExtensionSetting("preview_payload", None)
            
            # Reset form fields
            self._api_url_field.setText("https://oxytis.com/api/cve/analyze")
            self._api_token_field.setText("")
            self._privacy_combo.setSelectedItem("Redacted")
            self._preview_check.setSelected(True)
            
            self._results_area.append("[+] Settings cleared successfully\n")
            JOptionPane.showMessageDialog(self._main_panel, 
                "Settings cleared successfully!", 
                "Settings Cleared", 
                JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._results_area.append("[-] Error clearing settings: " + str(e) + "\n")
    
    def _test_api_connection(self):
        """Test the API connection"""
        def test_connection():
            try:
                api_url = self._api_url_field.getText().replace("/analyze", "/health")
                
                request = urllib2.Request(api_url)
                response = urllib2.urlopen(request, timeout=10)
                result = response.read()
                
                self._results_area.append("[+] API Connection Test:\n")
                self._results_area.append(result + "\n\n")
                
                JOptionPane.showMessageDialog(self._main_panel, 
                    "API connection successful!", 
                    "Connection Test", 
                    JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                error_msg = "API connection failed: " + str(e)
                self._results_area.append("[-] " + error_msg + "\n\n")
                JOptionPane.showMessageDialog(self._main_panel, 
                    error_msg, 
                    "Connection Error", 
                    JOptionPane.ERROR_MESSAGE)
        
        # Run in background thread
        thread = threading.Thread(target=test_connection)
        thread.daemon = True
        thread.start()
    def _severity_from_score(self, score):
        try:
            score = float(score)
        except:
            return "Unknown"

        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"
    def _analyze_cve(self):
        """Analyze a CVE using the Powertrain API"""
        def analyze():
            try:
                api_url = self._api_url_field.getText()
                api_token = self._api_token_field.getText()
                cve_id = self._cve_input_field.getText().strip()
                format_type = "json" 
                
                # Debug output
                print("[DEBUG] API URL: " + api_url)
                print("[DEBUG] API Token length: " + str(len(api_token)))
                print("[DEBUG] CVE ID: " + cve_id)
                
                if not api_token:
                    JOptionPane.showMessageDialog(self._main_panel, 
                        "Please enter an API token", 
                        "Missing Token", 
                        JOptionPane.WARNING_MESSAGE)
                    return
                
                if not cve_id or cve_id == "CVE-":
                    JOptionPane.showMessageDialog(self._main_panel, 
                        "Please enter a valid CVE ID", 
                        "Missing CVE ID", 
                        JOptionPane.WARNING_MESSAGE)
                    return
                
                # Prepare request
                data = {
                    "token": api_token,
                    "cve_id": cve_id,
                    "format": format_type
                }
                
                json_data = json.dumps(data)
                print("[DEBUG] Request data: " + json_data[:100] + "...")  # First 100 chars
                
                request = urllib2.Request(api_url)
                request.add_header('Content-Type', 'application/json')
                request.get_method = lambda: 'POST'
                
                self._results_area.append("[*] Analyzing " + cve_id + "...\n")
                
                response = urllib2.urlopen(request, json_data, timeout=30)
                result = response.read()
                
                # Parse and display results
                self._display_cve_results(cve_id, result)
                
            except urllib2.HTTPError as e:
                error_msg = "HTTP Error " + str(e.code) + ": " + str(e.reason)
                if e.code == 401:
                    error_msg += "\n\nThis is usually caused by:\n"
                    error_msg += "- Invalid API token\n"
                    error_msg += "- Token copied with extra spaces\n"
                    error_msg += "- Expired or revoked token\n"
                    error_msg += "\nPlease verify your API token is correct."
                
                self._results_area.append("[-] " + error_msg + "\n\n")
                JOptionPane.showMessageDialog(self._main_panel, 
                    error_msg, 
                    "API Error", 
                    JOptionPane.ERROR_MESSAGE)
                    
            except Exception as e:
                error_msg = "CVE analysis failed: " + str(e)
                self._results_area.append("[-] " + error_msg + "\n\n")
                JOptionPane.showMessageDialog(self._main_panel, 
                    error_msg, 
                    "Analysis Error", 
                    JOptionPane.ERROR_MESSAGE)
        
        # Run in background thread
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
        
    def _clean_text(self, text):
        """Clean text to handle Unicode characters safely"""
        if text is None:
            return "N/A"
        
        # Convert to string and handle Unicode
        text = unicode(text) if isinstance(text, str) else text
        
        # Replace common Unicode characters that cause issues
        replacements = {
            u'\u2013': '-',  # em dash
            u'\u2014': '-',  # em dash
            u'\u2018': "'",  # left single quote
            u'\u2019': "'",  # right single quote
            u'\u201c': '"',  # left double quote
            u'\u201d': '"',  # right double quote
            u'\u2022': '*',  # bullet point
        }
        
        for unicode_char, replacement in replacements.items():
            text = text.replace(unicode_char, replacement)
        
        # Remove any remaining problematic characters
        try:
            text.encode('ascii')
        except UnicodeEncodeError:
            # If still has Unicode issues, encode to ASCII with replacement
            text = text.encode('ascii', 'replace').decode('ascii')
        
        return text

    def _display_cve_results(self, cve_id, json_result):
        """Display formatted CVE analysis results with enhanced formatting"""
        try:
            data = json.loads(json_result)
            
            if data.get("status") == "success":
                cve_data = data.get("data", {})
                
                # Clean all text data first
                title = self._clean_text(cve_data.get("title", "N/A"))
                cvss_vector = self._clean_text(cve_data.get("cvss_vector", "N/A"))
                label = self._clean_text(cve_data.get("label", "N/A"))
                description = self._clean_text(cve_data.get("description", "No description available"))
                recommendation = self._clean_text(cve_data.get("recommendation", "No recommendations available"))
                notes = self._clean_text(cve_data.get("notes", ""))
                
                # Header with emphasis
                self._results_area.append("\n" + "=" * 80 + "\n")
                self._results_area.append("    POWERTRAIN CVE ANALYSIS: " + cve_id + "\n")
                self._results_area.append("=" * 80 + "\n\n")
                
                # Key Information Section
                self._results_area.append(">>> KEY INFORMATION <<<\n")
                self._results_area.append("-" * 25 + "\n")
                self._results_area.append("  Title: " + title + "\n\n")
                
                # Risk Scoring Section
                self._results_area.append(">>> RISK ASSESSMENT <<<\n") 
                self._results_area.append("-" * 25 + "\n")
                cvss_score = cve_data.get("cvss_score", "N/A")
                severity = self._severity_from_score(cvss_score)
                self._results_area.append("  CVSS Score:        " + str(cvss_score) + " (" + severity + ")\n")
                self._results_area.append("  CVSS Vector:       " + cvss_vector + "\n")
                self._results_area.append("  Oxytis Risk Score: " + str(cve_data.get("oxytis_risk_score", "N/A")) + "\n")
                self._results_area.append("  Residual Risk:     " + str(cve_data.get("residual_risk_score", "N/A")) + "\n")
                epss = cve_data.get("epss")
                percentile = cve_data.get("percentile")
                if epss is not None:
                    line = "  EPSS (30-day):     " + str(round(epss * 100, 2)) + "%"
                    if percentile is not None:
                        line += "  (percentile " + str(round(percentile * 100, 1)) + ")"
                    self._results_area.append(line + "\n")
                controls = cve_data.get("applied_controls")
                if controls:
                    self._results_area.append("  Controls Credited: " + ", ".join(controls) + "\n")
                self._results_area.append("  OWASP Category:    " + label + "\n\n")
                
                # Technical Analysis Section
                self._results_area.append(">>> TECHNICAL ANALYSIS <<<\n")
                self._results_area.append("-" * 28 + "\n")
                
                # Simple approach: Try to format HEXAD if found, otherwise display everything as-is
                if "HEXAD" in description:
                    try:
                        # Split on HEXAD and format the HEXAD section
                        parts = description.split("HEXAD")
                        if len(parts) > 1:
                            pre_hexad = parts[0].strip()
                            hexad_and_after = "HEXAD" + parts[1]
                            
                            # Display pre-HEXAD content with SOO highlighting
                            if pre_hexad:
                                pre_hexad = pre_hexad.replace("Subject", "**Subject**")
                                pre_hexad = pre_hexad.replace("Object", "**Object**")
                                pre_hexad = pre_hexad.replace("Opportunity", "**Opportunity**")
                                wrapped_pre = self._wrap_text(pre_hexad, 76)
                                self._results_area.append(self._indent_text(wrapped_pre, 2) + "\n\n")
                            
                            # Try to format HEXAD section
                            self._format_hexad_section(hexad_and_after)
                        else:
                            # HEXAD split failed, display everything normally
                            self._display_description_as_is(description)
                    except:
                        # Any error in HEXAD formatting, fall back to displaying as-is
                        self._display_description_as_is(description)
                else:
                    # No HEXAD found, display everything with basic SOO highlighting
                    self._display_description_as_is(description)
                
                # Recommendations Section
                self._results_area.append(">>> REMEDIATION RECOMMENDATIONS <<<\n")
                self._results_area.append("-" * 36 + "\n")
                wrapped_rec = self._wrap_text(recommendation, 76)
                self._results_area.append(self._indent_text(wrapped_rec, 2) + "\n\n")
                
                # Residual Risk Explanation Section
                explanation = self._clean_text(cve_data.get("residual_risk_explanation", ""))
                if explanation and explanation != "N/A":
                    self._results_area.append(">>> RESIDUAL RISK EXPLANATION <<<\n")
                    self._results_area.append("-" * 33 + "\n")
                    for para in explanation.split("\n\n"):
                        para = para.strip()
                        if para:
                            wrapped = self._wrap_text(para, 76)
                            self._results_area.append(self._indent_text(wrapped, 2) + "\n\n")
                

                
                # Additional Notes Section
                if notes and notes != "":
                    self._results_area.append(">>> ADDITIONAL NOTES <<<\n")
                    self._results_area.append("-" * 22 + "\n")
                    wrapped_notes = self._wrap_text(notes, 76)
                    self._results_area.append(self._indent_text(wrapped_notes, 2) + "\n\n")
                
                # Footer
                self._results_area.append("Analysis completed at: " + Date().toString() + "\n")
                self._results_area.append("=" * 80 + "\n\n")
                
            else:
                self._results_area.append("[-] Analysis failed: " + 
                    data.get("error", "Unknown error") + "\n\n")
                
        except Exception as e:
            self._results_area.append("[-] Error parsing results: " + str(e) + "\n\n")

    def _display_description_as_is(self, description):
        """Display description content as-is with basic SOO highlighting"""
        # Simple highlighting of SOO terms
        highlighted = description.replace("Subject", "**Subject**")
        highlighted = highlighted.replace("Object", "**Object**")
        highlighted = highlighted.replace("Opportunity", "**Opportunity**")
        
        wrapped_desc = self._wrap_text(highlighted, 76)
        self._results_area.append(self._indent_text(wrapped_desc, 2) + "\n\n")

    def _format_hexad_section(self, hexad_content):
        """Try to format HEXAD section, fall back gracefully if it fails"""
        try:
            self._results_area.append("  >>> HEXAD SECURITY PRIMITIVES <<<\n")
            self._results_area.append("  " + "-" * 34 + "\n")
            
            # Find where HEXAD content ends
            end_markers = ["The CVSS", "The vulnerable", "The Oxytis",
                           "OWASP", "Oxytis Risk Score", "Oxytis Risk"]
            hexad_end = len(hexad_content)
            
            for marker in end_markers:
                pos = hexad_content.find(marker)
                if pos != -1 and pos < hexad_end:
                    hexad_end = pos
            
            pure_hexad = hexad_content[:hexad_end]
            post_hexad = hexad_content[hexad_end:].strip()
            
            # Try to format HEXAD elements
            hexad_elements = ["Confidentiality", "Integrity", "Availability", 
                             "Possession", "Authenticity", "Utility"]
            
            found_any_elements = False
            for element in hexad_elements:
                if element in pure_hexad:
                    start_idx = pure_hexad.find(element)
                    if start_idx != -1:
                        # Find next element
                        next_idx = len(pure_hexad)
                        for next_elem in hexad_elements:
                            if next_elem != element:
                                next_pos = pure_hexad.find(next_elem, start_idx + 1)
                                if next_pos != -1 and next_pos < next_idx:
                                    next_idx = next_pos
                        
                        element_desc = pure_hexad[start_idx:next_idx].strip()
                        element_desc = element_desc.replace("**", "")
                        element_desc = " ".join(element_desc.split())
                        element_desc = element_desc.lstrip("-*\u2022 ").rstrip(" -*\u2022")
                        
                        if ":" in element_desc and len(element_desc) > len(element) + 10:
                            self._results_area.append("    * " + element_desc + "\n")
                            found_any_elements = True
            
            # If no elements found, just display the content as-is
            if not found_any_elements:
                wrapped_hexad = self._wrap_text(pure_hexad, 76)
                self._results_area.append(self._indent_text(wrapped_hexad, 4) + "\n")
            
            self._results_area.append("\n")
            
            # Display post-HEXAD content, but drop a redundant CVSS-vector restatement
            if post_hexad:
                low = post_hexad.lower()
                if not (low.startswith("the cvss") or low.startswith("the vulnerable")
                        or low.startswith("the oxytis")):
                    wrapped_post = self._wrap_text(post_hexad, 76)
                    self._results_area.append(self._indent_text(wrapped_post, 2) + "\n\n")
                
        except:
            # If HEXAD formatting fails completely, just display as normal text
            wrapped_content = self._wrap_text(hexad_content, 76)
            self._results_area.append(self._indent_text(wrapped_content, 2) + "\n\n")
            
    def _indent_text(self, text, spaces):
        """Add indentation to text"""
        indent = " " * spaces
        lines = text.split("\n")
        return "\n".join(indent + line for line in lines)
    
    def _wrap_text(self, text, width):
        """Text wrapping with markdown cleanup"""
        # Clean up text first
        text = text.replace("**", "").replace("*", "")  # Remove markdown formatting
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + 1 <= width:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(" ".join(current_line))
        
        return "\n".join(lines)
    
    # ------------------------------------------------------------------
    # Finding (no-CVE) assessment -> /api/finding/analyze
    # ------------------------------------------------------------------
    def _cwe_for_issue(self, name):
        """Map a Burp Scanner issue name to a CWE, or None to let the model infer."""
        if not name:
            return None
        n = name.lower()
        for needle, cwe in _ISSUE_CWE:
            if needle in n:
                return cwe
        return None

    def _strip_html(self, html):
        """Crude HTML -> text for issue detail/background (model input only)."""
        if not html:
            return ""
        text = re.sub(r"<[^>]+>", " ", html)
        for a, b in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                     ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " ")]:
            text = text.replace(a, b)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
        return text.strip()

    def _issue_evidence(self, issue):
        """Raw first request/response pair (truncated). Used only in 'Raw' mode."""
        try:
            msgs = issue.getHttpMessages()
            if not msgs or len(msgs) == 0:
                return "(no request/response captured)"
            m = msgs[0]
            parts = []
            req = m.getRequest()
            if req:
                parts.append("=== REQUEST ===\n" + self._helpers.bytesToString(req)[:2000])
            resp = m.getResponse()
            if resp:
                parts.append("=== RESPONSE ===\n" + self._helpers.bytesToString(resp)[:2000])
            return "\n\n".join(parts) if parts else "(no request/response captured)"
        except Exception as e:
            print("[-] Error extracting evidence: " + str(e))
            return "(evidence extraction failed)"

    # ---- privacy: redaction + structured evidence -------------------------------

    def _redact(self, text, host=None):
        """Mask identifying values but keep their *shape* (type + length) so the model
        can still reason about e.g. a 32-hex hash or a JWT without seeing it."""
        if not text:
            return ""
        t = text
        if host:
            t = re.sub(re.escape(host), "[host]", t, flags=re.I)
        t = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "[jwt]", t)
        t = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", t)
        t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[ipv4]", t)
        t = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "[mac]", t)
        t = re.sub(r"(?i)(serial(?:\s*(?:number|no\.?|#))?\s*[:=(]?\s*)([A-Za-z0-9][A-Za-z0-9-]{3,})",
                   lambda m: m.group(1) + "[serial]", t)
        t = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[uuid]", t)
        t = re.sub(r"\b[0-9a-fA-F]{32,}\b", lambda m: "[hex:%d]" % len(m.group(0)), t)
        # base64: require at least one digit so camelCase identifiers (endpoint/function names) survive
        t = re.sub(r"(?<![A-Za-z0-9+/=])(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])",
                   lambda m: "[b64:%d]" % len(m.group(0)), t)
        t = _SENSITIVE_KV.sub(lambda m: m.group(1) + "[redacted]", t)
        return t

    def _shape_path(self, path):
        """Tokenize path segments that look like identifiers."""
        segs = []
        for seg in path.split("/"):
            if not seg:
                segs.append(seg); continue
            if re.match(r"^\d+$", seg):
                segs.append("{n}")
            elif re.match(r"^[0-9a-fA-F-]{16,}$", seg) or re.match(r"^(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}$", seg):
                segs.append("{id}")
            else:
                segs.append(seg)
        return "/".join(segs)

    def _shape_headers(self, headers, is_request):
        """Header names always; values only from the allow-list. Auth scheme kept, credential dropped."""
        out = []
        for h in headers[1:]:  # [0] is the request/status line
            if ":" not in h:
                continue
            name, val = h.split(":", 1)
            lname = name.strip().lower(); val = val.strip()
            if lname in ("authorization", "proxy-authorization", "www-authenticate"):
                out.append(name.strip() + ": " + (val.split(" ", 1)[0] if val else "") + " [redacted]")
            elif lname == "cookie":
                names = [c.split("=", 1)[0].strip() for c in val.split(";") if c.strip()]
                out.append("Cookie: " + ", ".join(names) + " (names only)")
            elif lname == "set-cookie":
                parts = [p.strip() for p in val.split(";")]
                cname = parts[0].split("=", 1)[0] if parts else ""
                flags = [p.split("=", 1)[0] for p in parts[1:]]
                out.append("Set-Cookie: " + cname + "=[redacted]; " + "; ".join(flags))
            elif lname in _HEADER_VALUE_ALLOW:
                out.append(name.strip() + ": " + val)
            elif lname == "host":
                out.append("Host: [host]")
            else:
                out.append(name.strip() + ": [omitted]")
        return out

    def _markers(self, m, which):
        """Burp-highlighted byte ranges (what the Scanner actually flagged)."""
        try:
            fn = m.getRequestMarkers if which == "req" else m.getResponseMarkers
            ranges = fn()
            return list(ranges) if ranges else []
        except Exception:
            return []

    def _structured_evidence(self, issue, mode):
        """Shape-only view of the first request/response, plus (Redacted mode) the
        Scanner-highlighted snippets with values masked. No bodies, no host, no cookies."""
        try:
            msgs = issue.getHttpMessages()
            if not msgs or len(msgs) == 0:
                return "(no request/response captured)"
            m = msgs[0]
            svc = m.getHttpService()
            host = svc.getHost() if svc else None
            lines = []

            req = m.getRequest()
            if req:
                ri = self._helpers.analyzeRequest(m)
                url = ri.getUrl()
                lines.append("=== REQUEST (shape) ===")
                lines.append("%s %s://[host]:%s%s" % (ri.getMethod(), url.getProtocol(),
                             url.getPort(), self._shape_path(url.getPath() or "/")))
                params = []
                for p in ri.getParameters():
                    ptype = {0: "url", 1: "body", 2: "cookie", 6: "json", 3: "xml", 5: "multipart"}.get(p.getType(), "other")
                    params.append("%s(%s)" % (p.getName(), ptype))
                if params:
                    lines.append("Params: " + ", ".join(params))
                lines.extend(self._shape_headers(ri.getHeaders(), True))
                body_len = len(req) - ri.getBodyOffset()
                lines.append("Body: %d bytes [omitted]" % max(body_len, 0))
                if mode == "Redacted":
                    rs = self._helpers.bytesToString(req)
                    for rng in self._markers(m, "req")[:_MAX_SNIPPETS]:
                        snip = rs[rng[0]:rng[1]][:_MAX_SNIPPET]
                        lines.append("Flagged: " + self._redact(snip, host))

            resp = m.getResponse()
            if resp:
                rsi = self._helpers.analyzeResponse(resp)
                lines.append("")
                lines.append("=== RESPONSE (shape) ===")
                lines.append("Status: %d  MIME: %s/%s  Body: %d bytes [omitted]" % (
                    rsi.getStatusCode(), rsi.getStatedMimeType(), rsi.getInferredMimeType(),
                    max(len(resp) - rsi.getBodyOffset(), 0)))
                lines.extend(self._shape_headers(rsi.getHeaders(), False))
                if mode == "Redacted":
                    rs = self._helpers.bytesToString(resp)
                    for rng in self._markers(m, "resp")[:_MAX_SNIPPETS]:
                        snip = rs[rng[0]:rng[1]][:_MAX_SNIPPET]
                        lines.append("Flagged: " + self._redact(snip, host))

            return "\n".join(lines) if lines else "(no request/response captured)"
        except Exception as e:
            print("[-] Error building structured evidence: " + str(e))
            return "(evidence extraction failed)"

    def _build_finding_payload(self, issue, api_token):
        """Assemble the exact JSON sent to /api/finding/analyze for the selected privacy mode."""
        mode = str(self._privacy_combo.getSelectedItem())
        name = issue.getIssueName()
        cwe = self._cwe_for_issue(name)
        detail = self._strip_html(issue.getIssueDetail() or "")
        background = self._strip_html(issue.getIssueBackground() or "")
        if background:
            detail = (detail + "\n\n" + background).strip()
        detail = _PRIOR_ASSESSMENT.sub("", detail).strip()
        if mode == "Raw":
            evidence = self._issue_evidence(issue)
        else:
            try:
                host = issue.getHttpService().getHost()
            except Exception:
                host = None
            detail = self._redact(detail, host)
            evidence = self._structured_evidence(issue, mode)
        return {
            "token": api_token,
            "name": name,
            "cwe": cwe,
            "detail": detail,
            "evidence": evidence,
            "evidence_mode": mode.lower(),
            "exposure": str(self._exposure_combo.getSelectedItem()).lower(),
            "controls": str(self._controls_combo.getSelectedItem()).lower(),
        }

    def _confirm_payload(self, data):
        """Show the outbound payload (token masked) and let the tester cancel."""
        shown = dict(data); shown["token"] = "[configured]"
        area = JTextArea(json.dumps(shown, indent=2), 30, 90)
        area.setEditable(False)
        area.setFont(Font("Monospaced", Font.PLAIN, 11))
        choice = JOptionPane.showConfirmDialog(self._main_panel, JScrollPane(area),
            "Powertrain: this is what will be sent", JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE)
        return choice == JOptionPane.OK_OPTION

    def _analyze_finding(self, issue):
        """Assess a Burp scan issue (no CVE) via the Powertrain finding endpoint."""
        api_url = self._api_url_field.getText()
        api_token = self._api_token_field.getText()
        finding_url = api_url.replace("/cve/", "/finding/")

        if not api_token:
            JOptionPane.showMessageDialog(self._main_panel,
                "Please enter an API token", "Missing Token",
                JOptionPane.WARNING_MESSAGE)
            return

        # Payload is built (and optionally previewed) on the calling thread so the
        # tester sees exactly what leaves Burp before anything is sent.
        data = self._build_finding_payload(issue, api_token)
        if self._preview_check.isSelected() and not self._confirm_payload(data):
            self._results_area.append("[*] Assessment cancelled by user\n")
            return
        name = data["name"]; cwe = data["cwe"]
        json_data = json.dumps(data)

        def analyze():
            try:
                request = urllib2.Request(finding_url)
                request.add_header("Content-Type", "application/json")
                request.get_method = lambda: "POST"

                self._results_area.append("[*] Assessing finding: " + name +
                                          (" (" + cwe + ")" if cwe else "") +
                                          " [evidence: " + data["evidence_mode"] + "] ...\n")
                response = urllib2.urlopen(request, json_data, timeout=60)
                result = response.read()
                self._display_finding_results(name, result)

            except urllib2.HTTPError as e:
                error_msg = "HTTP Error " + str(e.code) + ": " + str(e.reason)
                self._results_area.append("[-] " + error_msg + "\n\n")
                JOptionPane.showMessageDialog(self._main_panel, error_msg,
                    "API Error", JOptionPane.ERROR_MESSAGE)
            except Exception as e:
                error_msg = "Finding assessment failed: " + str(e)
                self._results_area.append("[-] " + error_msg + "\n\n")
                JOptionPane.showMessageDialog(self._main_panel, error_msg,
                    "Analysis Error", JOptionPane.ERROR_MESSAGE)

        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()

    def _display_finding_results(self, issue_name, json_result):
        """Render an estimated finding assessment, reusing the CVE formatters."""
        try:
            data = json.loads(json_result)
            if data.get("status") != "success":
                self._results_area.append("[-] Assessment failed: " +
                    str(data.get("error", "Unknown error")) + "\n\n")
                return
            fd = data.get("data", {})

            title = self._clean_text(fd.get("title", issue_name))
            cvss_vector = self._clean_text(fd.get("cvss_vector", "N/A"))
            label = self._clean_text(fd.get("label", "N/A"))
            description = self._clean_text(fd.get("description", "No description available"))
            recommendation = self._clean_text(fd.get("recommendation", "No recommendations available"))
            notes = self._clean_text(fd.get("notes", ""))
            cvss_score = fd.get("cvss_score")
            severity = self._clean_text(fd.get("cvss_severity") or self._severity_from_score(cvss_score))

            self._results_area.append("\n" + "=" * 80 + "\n")
            self._results_area.append("    POWERTRAIN FINDING ASSESSMENT (ESTIMATED): " + issue_name + "\n")
            self._results_area.append("=" * 80 + "\n\n")

            self._results_area.append(">>> KEY INFORMATION <<<\n")
            self._results_area.append("-" * 25 + "\n")
            self._results_area.append("  Title: " + title + "\n")
            self._results_area.append("  NOTE:  No published CVE - CVSS is a Tally estimate from the finding evidence.\n\n")

            self._results_area.append(">>> RISK ASSESSMENT <<<\n")
            self._results_area.append("-" * 25 + "\n")
            if cvss_score is None:
                self._results_area.append("  CVSS (est. v4.0):  N/A (could not derive a vector)\n")
            else:
                self._results_area.append("  CVSS (est. v4.0):  " + str(cvss_score) + " (" + severity + ")\n")
            self._results_area.append("  CVSS Vector:       " + cvss_vector + "\n")
            # Oxytis Risk is a contextual prioritization adjustment to the CVSS base
            # (exposure + control effectiveness), not a CVSS score. Show its inputs.
            risk = fd.get("oxytis_risk_score", "N/A")
            expo = str(self._exposure_combo.getSelectedItem()).lower()
            ctrl = str(self._controls_combo.getSelectedItem()).lower()
            self._results_area.append("  Oxytis Risk (prioritization, not CVSS): " + str(risk) +
                "  [CVSS base adjusted for " + ctrl + " controls, " + expo + " exposure]\n")
            self._results_area.append("  OWASP Category:    " + label + "\n")
            # Subsequent-system audit trail (server enforces S*=N when no distinct system is named)
            subsequent = fd.get("subsequent_system")
            self._results_area.append("  Subsequent System: " +
                (self._clean_text(subsequent) if subsequent else "none named") + "\n")
            if fd.get("subsequent_impact_zeroed"):
                self._results_area.append("  NOTE: model judged " +
                    self._clean_text(fd.get("cvss_vector_model", "?")) +
                    " but S* zeroed (no subsequent system named)\n")
            self._results_area.append("\n")

            self._results_area.append(">>> TECHNICAL ANALYSIS <<<\n")
            self._results_area.append("-" * 28 + "\n")
            if "HEXAD" in description:
                try:
                    parts = description.split("HEXAD")
                    if len(parts) > 1:
                        pre = parts[0].strip()
                        pre = re.sub(r"\s*(?:in terms of\s+)?the\s*$", "", pre, flags=re.I).strip()
                        if pre:
                            pre = pre.replace("Subject", "**Subject**").replace("Object", "**Object**").replace("Opportunity", "**Opportunity**")
                            self._results_area.append(self._indent_text(self._wrap_text(pre, 76), 2) + "\n\n")
                        self._format_hexad_section("HEXAD" + parts[1])
                    else:
                        self._display_description_as_is(description)
                except:
                    self._display_description_as_is(description)
            else:
                self._display_description_as_is(description)

            self._results_area.append(">>> REMEDIATION RECOMMENDATIONS <<<\n")
            self._results_area.append("-" * 36 + "\n")
            self._results_area.append(self._indent_text(self._wrap_text(recommendation, 76), 2) + "\n\n")

            if notes and notes != "":
                self._results_area.append(">>> ADDITIONAL NOTES <<<\n")
                self._results_area.append("-" * 22 + "\n")
                self._results_area.append(self._indent_text(self._wrap_text(notes, 76), 2) + "\n\n")

            self._results_area.append("Assessment completed at: " + Date().toString() + "\n")
            self._results_area.append("=" * 80 + "\n\n")
        except Exception as e:
            self._results_area.append("[-] Error parsing finding results: " + str(e) + "\n\n")

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []

        # 1) Selected CVE text -> CVE analysis (existing behavior)
        selected_text = self._get_selected_text(invocation)
        if selected_text and self._is_cve_format(selected_text):
            menu_item = JMenuItem("Analyze with Powertrain: " + selected_text)
            menu_item.addActionListener(CVEMenuActionListener(self, selected_text))
            menu_items.append(menu_item)

        # 2) Selected scan issues -> finding assessment (estimated CVSS)
        try:
            issues = invocation.getSelectedIssues()
        except:
            issues = None
        if issues is not None and len(issues) > 0:
            # one issue can have many instances (same name, many URLs); this extension
            # assesses the finding TYPE, so collapse to one menu item per issue name.
            seen = set()
            for issue in issues:
                iname = issue.getIssueName()
                if iname in seen:
                    continue
                seen.add(iname)
                item = JMenuItem("Assess with Tally (estimate CVSS): " + iname)
                item.addActionListener(FindingMenuActionListener(self, issue))
                menu_items.append(item)

        return menu_items if menu_items else None
    
    def _get_selected_text(self, invocation):
        """Extract selected text from request/response"""
        try:
            bounds = invocation.getSelectionBounds()
            if not bounds:
                return None
                
            context = invocation.getInvocationContext()
            
            # Handle different context types
            if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, 
                          invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
                message = invocation.getSelectedMessages()[0].getRequest()
            elif context in [invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
                            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                message = invocation.getSelectedMessages()[0].getResponse()
            else:
                # For other contexts (proxy history, site map, etc.)
                # Try to get from either request or response
                selected_messages = invocation.getSelectedMessages()
                if selected_messages and len(selected_messages) > 0:
                    # Try response first, then request
                    message = selected_messages[0].getResponse()
                    if not message:
                        message = selected_messages[0].getRequest()
                else:
                    return None
            
            if message:
                selected_text = self._helpers.bytesToString(message)[bounds[0]:bounds[1]]
                return selected_text.strip()
                
        except Exception as e:
            print("[-] Error getting selected text: " + str(e))
            
        return None
        
    def _is_cve_format(self, text):
        """Check if text matches CVE format"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.match(cve_pattern, text, re.IGNORECASE) is not None
    
    def analyze_cve_from_context(self, cve_id):
        """Analyze CVE from context menu selection"""
        self._cve_input_field.setText(cve_id)
        self._analyze_cve()
    
    # ITab implementation
    def getTabCaption(self):
        return "Powertrain"
    
    def getUiComponent(self):
        return self._main_panel
    
    # IHttpListener implementation (for automatic CVE detection)
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages to detect CVE references"""
        # This could be extended to automatically detect CVE IDs in responses
        pass

class CVEMenuActionListener(ActionListener):
    """Action listener for context menu CVE analysis"""
    
    def __init__(self, extender, cve_id):
        self.extender = extender
        self.cve_id = cve_id
    
    def actionPerformed(self, event):
        self.extender.analyze_cve_from_context(self.cve_id)

class FindingMenuActionListener(ActionListener):
    """Action listener for context-menu finding assessment (Burp scan issues)."""

    def __init__(self, extender, issue):
        self.extender = extender
        self.issue = issue

    def actionPerformed(self, event):
        self.extender._analyze_finding(self.issue)

# Document change listener for auto-saving settings
class SettingsChangeListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender
    
    def insertUpdate(self, e):
        self.extender._save_settings()
    
    def removeUpdate(self, e):
        self.extender._save_settings()
    
    def changedUpdate(self, e):
        self.extender._save_settings()
