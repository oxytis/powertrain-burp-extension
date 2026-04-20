#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Powertrain CVE Analysis Extension for Burp Suite
Integrates Oxytis Powertrain CVE intelligence directly into Burp Suite
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JLabel, JTextField, JButton, JTextArea, 
                        JScrollPane, BoxLayout, JMenuItem, JOptionPane,
                        BorderFactory, SwingConstants, JComboBox)
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, FlowLayout, Dimension, Color, Font
from java.awt.event import ActionListener
from javax.swing.border import EmptyBorder
from java.util import Date
import json
import urllib2
import threading

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, ActionListener):
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension with persistent settings"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Powertrain CVE Analyzer")
        
        # Load saved settings
        self._load_settings()
        
        # Initialize UI
        self._init_ui()
        
        # Register as HTTP listener and context menu factory
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        # Add custom tab
        callbacks.addSuiteTab(self)
        
        print("[+] Powertrain CVE Analyzer loaded successfully")
        print("[+] Configure API settings in the Powertrain CVE tab")
    
    def _load_settings(self):
        """Load saved settings from Burp's extension settings"""
        try:
            # Load API URL
            saved_url = self._callbacks.loadExtensionSetting("api_url")
            self._saved_api_url = saved_url if saved_url else "https://oxytis.com/api/cve/analyze"
            
            # Load API Token
            saved_token = self._callbacks.loadExtensionSetting("api_token")
            self._saved_api_token = saved_token if saved_token else ""
            
            print("[+] Settings loaded from Burp configuration")
        except Exception as e:
            print("[-] Error loading settings: " + str(e))
            self._saved_api_url = "https://oxytis.com/api/cve/analyze"
            self._saved_api_token = ""
    
    def _save_settings(self):
        """Save current settings to Burp's extension settings"""
        try:
            # Save API URL
            api_url = self._api_url_field.getText()
            self._callbacks.saveExtensionSetting("api_url", api_url)
            
            # Save API Token
            api_token = self._api_token_field.getText()
            self._callbacks.saveExtensionSetting("api_token", api_token)
            
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
        header_panel.setBorder(BorderFactory.createTitledBorder("Powertrain CVE Intelligence"))
        
        title_label = JLabel("Oxytis Powertrain CVE Analyzer")
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
        results_panel.setBorder(BorderFactory.createTitledBorder("CVE Analysis Results"))
        
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
    
    def _clear_settings(self):
        """Clear all saved settings"""
        try:
            self._callbacks.saveExtensionSetting("api_url", None)
            self._callbacks.saveExtensionSetting("api_token", None)
            
            # Reset form fields
            self._api_url_field.setText("https://oxytis.com/api/cve/analyze")
            self._api_token_field.setText("")
            
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
            end_markers = ["The CVSS", "OWASP", "Oxytis Risk Score"]
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
                        element_desc = element_desc.replace("**", "").replace("- ", "").replace(" -", "")
                        element_desc = " ".join(element_desc.split())
                        
                        if ":" in element_desc and len(element_desc) > len(element) + 10:
                            self._results_area.append("    * " + element_desc + "\n")
                            found_any_elements = True
            
            # If no elements found, just display the content as-is
            if not found_any_elements:
                wrapped_hexad = self._wrap_text(pure_hexad, 76)
                self._results_area.append(self._indent_text(wrapped_hexad, 4) + "\n")
            
            self._results_area.append("\n")
            
            # Display post-HEXAD content
            if post_hexad:
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
    
    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []
        
        # Get selected text from request/response
        selected_text = self._get_selected_text(invocation)
        
        if selected_text and self._is_cve_format(selected_text):
            menu_item = JMenuItem("Analyze with Powertrain: " + selected_text)
            menu_item.addActionListener(CVEMenuActionListener(self, selected_text))
            menu_items.append(menu_item)
        
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
        return "Powertrain CVE"
    
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
