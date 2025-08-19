import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import subprocess
import webbrowser
from pathlib import Path
import json
import os
import sys
import csv
import re

# FIXED: Import SimplePDFReporter correctly
try:
    from simple_pdf_reporter import SimplePDFReporter
    SIMPLE_PDF_AVAILABLE = True
except ImportError:
    SIMPLE_PDF_AVAILABLE = False

def safe_import(module_name, class_name=None):
    """Safely import modules with better error handling."""
    try:
        if class_name:
            module = __import__(module_name, fromlist=[class_name])
            return getattr(module, class_name)
        else:
            return __import__(module_name)
    except ImportError as e:
        print(f"Warning: Could not import {module_name}: {e}")
        return None
    except Exception as e:
        print(f"Error importing {module_name}: {e}")
        return None

class ComplianceChecker:
    """Built-in compliance checker for CMMC Level 1 requirements."""
    
    def __init__(self):
        self.cmmc_controls = {
            'AC.L1-3.1.1': {
                'name': 'Access Control Policy',
                'description': 'Limit system access to authorized users',
                'check_function': self.check_access_control
            },
            'AC.L1-3.1.2': {
                'name': 'Account Management', 
                'description': 'Limit system access to authorized users',
                'check_function': self.check_account_management
            },
            'IA.L1-3.5.1': {
                'name': 'User Identification',
                'description': 'Identify system users',
                'check_function': self.check_user_identification
            },
            'IA.L1-3.5.2': {
                'name': 'User Authentication',
                'description': 'Authenticate system users',
                'check_function': self.check_user_authentication
            },
            'SC.L1-3.13.1': {
                'name': 'Boundary Protection',
                'description': 'Monitor and control network communications',
                'check_function': self.check_boundary_protection
            },
            'SC.L1-3.13.5': {
                'name': 'Public Access Point Controls',
                'description': 'Deny network communications by default',
                'check_function': self.check_public_access_controls
            },
            'CM.L1-3.4.1': {
                'name': 'Configuration Management',
                'description': 'Maintain baseline configurations',
                'check_function': self.check_configuration_management
            }
        }
    
    def check_config_compliance(self, current_config_path, baseline_config_path=None, skip_connectivity=True):
        """Check configuration compliance against CMMC Level 1 controls."""
        try:
            print(f"🔍 Checking compliance for: {current_config_path}")
            
            # Read configuration file
            with open(current_config_path, 'r', encoding='utf-8', errors='ignore') as f:
                config_content = f.read()
            
            # Extract hostname
            hostname_match = re.search(r'hostname\s+(\S+)', config_content, re.IGNORECASE)
            hostname = hostname_match.group(1) if hostname_match else Path(current_config_path).stem
            
            # Initialize result
            result = {
                'hostname': hostname,
                'file_path': current_config_path,
                'checks': {},
                'issues': [],
                'score': 0,
                'compliant': False,
                'vendor_display': self.detect_vendor(config_content)
            }
            
            # Run compliance checks
            total_controls = len(self.cmmc_controls)
            passed_controls = 0
            
            # FIXED: Ensure all check data is preserved for dashboard
            for control_id, control_info in self.cmmc_controls.items():
                try:
                    check_result = control_info['check_function'](config_content)
                    
                    # Ensure check_result has required fields
                    if not isinstance(check_result, dict):
                        check_result = {'passed': False, 'details': 'Invalid check result', 'issues': ['Check function error']}
                    
                    # Store detailed check results - FIXED: Include all check data for dashboard
                    result['checks'][control_id] = {
                        'name': control_info['name'],
                        'description': control_info['description'],
                        'passed': check_result.get('passed', False),
                        'details': check_result.get('details', ''),
                        'issues': check_result.get('issues', []),
                        # FIXED: Include all check-specific data that dashboard expects
                        **{k: v for k, v in check_result.items() if k not in ['passed', 'details', 'issues']}
                    }
                    
                    if check_result.get('passed', False):
                        passed_controls += 1
                        print(f"  ✅ {control_id}: PASS")
                    else:
                        result['issues'].extend(check_result.get('issues', []))
                        print(f"  ❌ {control_id}: FAIL - {', '.join(check_result.get('issues', []))}")
                        
                except Exception as e:
                    print(f"  ❌ {control_id}: ERROR - {e}")
                    result['checks'][control_id] = {
                        'name': control_info['name'],
                        'description': control_info['description'],
                        'passed': False,
                        'details': f'Check error: {e}',
                        'issues': [f'Error running check: {e}']
                    }
                    result['issues'].append(f'{control_id}: Error running check')
            
            # FIXED: Calculate score correctly based on actual results
            result['score'] = int((passed_controls / total_controls) * 100) if total_controls > 0 else 0
            result['compliant'] = result['score'] >= 80  # 80% threshold for compliance
            
            print(f"✅ {hostname}: {result['score']}% compliant ({passed_controls}/{total_controls} controls)")
            
            return result
            
        except Exception as e:
            print(f"❌ Error checking {current_config_path}: {e}")
            return {
                'hostname': Path(current_config_path).stem,
                'file_path': current_config_path,
                'checks': {},
                'issues': [f"Error reading configuration: {e}"],
                'score': 0,
                'compliant': False,
                'vendor_display': 'Unknown'
            }
    
    def detect_vendor(self, config_content):
        """Detect network device vendor from configuration syntax."""
        if 'version 15' in config_content or 'version 16' in config_content or 'version 17' in config_content:
            return 'Cisco IOS'
        elif '! Arista' in config_content or 'management api http' in config_content:
            return 'Arista EOS'
        elif 'version ' in config_content and 'set' in config_content:
            return 'Juniper Junos'
        elif 'interface Management' in config_content:
            return 'Generic Switch'
        else:
            return 'Generic'

    def check_access_control(self, config):
        """Check AC.L1-3.1.1 - Access Control Policy implementation."""
        issues = []
        passed = True
        
        # Check for AAA authentication
        aaa_configured = 'aaa authentication' in config
        if not aaa_configured:
            issues.append("AAA authentication not configured")
            passed = False
        
        # Check for TACACS servers
        tacacs_servers = []
        if 'tacacs-server' in config or 'tacacs server' in config:
            # Extract TACACS server IPs (simplified)
            tacacs_matches = re.findall(r'tacacs(?:-server)?\s+host\s+(\S+)', config, re.IGNORECASE)
            tacacs_servers = tacacs_matches
        
        if not tacacs_servers:
            issues.append("No TACACS+ servers configured")
        
        return {
            'passed': passed,
            'details': "Checks for AAA authentication and TACACS+ servers",
            'issues': issues,
            'aaa_configured': aaa_configured,
            'tacacs_servers': tacacs_servers
        }
    
    def check_account_management(self, config):
        """Check AC.L1-3.1.2 - Account Management."""
        issues = []
        passed = True
        
        # Check for enable secret
        enable_secret_present = 'enable secret' in config
        if not enable_secret_present:
            issues.append("Enable secret not configured")
            passed = False
        
        # Check for Telnet (should be disabled)
        telnet_enabled = ('transport input telnet' in config or 
                         ('transport input all' in config and 'no telnet' not in config))
        no_telnet = not telnet_enabled
        
        if telnet_enabled:
            issues.append("Telnet access enabled (security risk)")
        
        return {
            'passed': passed,
            'details': "Checks for enable secret and secure transport",
            'issues': issues,
            'enable_secret_present': enable_secret_present,
            'no_telnet': no_telnet
        }
    
    def check_user_identification(self, config):
        """Check IA.L1-3.5.1 - User Identification."""
        issues = []
        user_identification = 'username ' in config
        passed = user_identification
        
        if not user_identification:
            issues.append("No user identification mechanism found")
            
        return {
            'passed': passed,
            'details': "Checks for user identification systems",
            'issues': issues,
            'user_identification': user_identification
        }
    
    def check_user_authentication(self, config):
        """Check IA.L1-3.5.2 - User Authentication.""" 
        issues = []
        passed = True
        
        # Check for enable secret or password
        enable_auth = 'enable secret' in config or 'enable password' in config
        if not enable_auth:
            issues.append("Missing enable secret/password")
            passed = False
        
        # Check for authentication mechanism
        auth_configured = 'aaa authentication' in config or 'username ' in config
        if not auth_configured:
            issues.append("No authentication mechanism configured")
            passed = False
        
        return {
            'passed': passed,
            'details': "Checks for authentication mechanisms and password security",
            'issues': issues,
            'authentication_configured': auth_configured
        }
    
    def check_boundary_protection(self, config):
        """Check SC.L1-3.13.1 - Boundary Protection."""
        issues = []
        
        # Check for access lists
        acls_present = 'ip access-list' in config or 'access-list' in config
        ssh_mgmt = 'transport input ssh' in config
        
        passed = acls_present and ssh_mgmt
        
        if not acls_present:
            issues.append("No access control lists found for boundary protection")
        
        if not ssh_mgmt:
            issues.append("SSH-only management not configured")
        
        return {
            'passed': passed,
            'details': "Checks for network boundary protection mechanisms",
            'issues': issues,
            'acls_present_and_applied': acls_present,
            'ssh_mgmt': ssh_mgmt
        }
    
    def check_public_access_controls(self, config):
        """Check SC.L1-3.13.5 - Public Access Point Controls."""
        issues = []
        
        # Check for DMZ interfaces with ACLs (simplified check)
        dmz_interfaces_without_acl = []
        
        # Look for interfaces that might be DMZ without ACLs
        interface_matches = re.findall(r'interface\s+(\S+.*?)\n(.*?)(?=interface|\Z)', config, re.DOTALL | re.IGNORECASE)
        
        for interface_name, interface_config in interface_matches:
            if ('dmz' in interface_name.lower() or 
                'outside' in interface_config.lower() or
                'wan' in interface_config.lower()):
                if 'ip access-group' not in interface_config:
                    dmz_interfaces_without_acl.append(interface_name)
        
        passed = len(dmz_interfaces_without_acl) == 0
        
        if dmz_interfaces_without_acl:
            issues.append(f"DMZ/public interfaces without ACLs: {', '.join(dmz_interfaces_without_acl)}")
        
        return {
            'passed': passed,
            'details': "Checks for public access point controls",
            'issues': issues,
            'dmz_interfaces_without_acl': dmz_interfaces_without_acl
        }
    
    def check_configuration_management(self, config):
        """Check CM.L1-3.4.1 - Configuration Management."""
        issues = []
        passed = True
        
        # Simplified baseline check - in reality this would compare against baseline files
        missing_lines = []
        extra_lines = []
        
        # Basic checks for standard configurations
        if 'service timestamps' not in config:
            missing_lines.append("service timestamps")
        if 'logging' not in config:
            missing_lines.append("logging configuration")
        
        if missing_lines:
            issues.append(f"Missing baseline configurations: {len(missing_lines)} items")
            passed = False
        
        return {
            'passed': passed,
            'details': "Checks for configuration management compliance",
            'issues': issues,
            'missing_lines': missing_lines,
            'extra_lines': extra_lines
        }

class ModernCMMCGUI:
    def __init__(self):
        self.root = tk.Tk()
        
        # Initialize compliance checker
        self.compliance_checker = ComplianceChecker()
        
        # Initialize enhanced reporting support
        self.initialize_enhanced_reporting()
        
        # Initialize vendor support
        self.initialize_vendor_support()
        
        # Initialize processing flag early to prevent old demo timers
        self.processing = False
        self.stop_requested = False
        
        # Store latest results for enhanced dashboard generation
        self.latest_results = []
        
        # Then setup the rest
        self.setup_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        
        print("🧹 GUI initialization complete")
    
    def initialize_enhanced_reporting(self):
        """Initialize enhanced reporting capabilities."""
        try:
            # Try to import enhanced dashboard from the same directory
            from enhanced_dashboard_generator import EnhancedCMMCDashboard
            self.EnhancedDashboard = EnhancedCMMCDashboard
            
            # FIXED: Use SimplePDFReporter instead of non-existent EnhancedPDFReporter
            if SIMPLE_PDF_AVAILABLE:
                self.SimplePDFReporter = SimplePDFReporter
                self.pdf_reporter_available = True
                print("✅ PDF reporting (SimplePDFReporter) enabled")
            else:
                self.SimplePDFReporter = None
                self.pdf_reporter_available = False
                print("⚠️ PDF reporting not available - install reportlab")
            
            self.enhanced_reporting = True
            print("✅ Enhanced reporting capabilities enabled")
                
        except Exception as e:
            self.enhanced_reporting = False
            self.pdf_reporter_available = False
            print(f"⚠️ Enhanced reporting not available: {e}")
            print("   Using basic reporting")
    
    def initialize_vendor_support(self):
        """Initialize vendor manager and support flags."""
        try:
            VendorManager = safe_import('enhanced_features.vendor_manager', 'VendorManager')
            VendorType = safe_import('enhanced_features.vendor_manager', 'VendorType')
            
            if VendorManager and VendorType:
                self.vendor_manager = VendorManager()
                self.vendor_support = True
                print("✅ Multi-vendor support enabled")
            else:
                raise ImportError("VendorManager or VendorType not available")
                
        except Exception as e:
            self.vendor_manager = None
            self.vendor_support = False
            print(f"⚠️ Multi-vendor support not available: {e}")
            print("   Running in basic mode")
        
    def setup_window(self):
        """Configure the main window."""
        self.root.title("CMMC 2.0 Level 1 Compliance Tool - Enhanced")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Center window on screen
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - self.root.winfo_width()) // 2
        y = (screen_height - self.root.winfo_height()) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Configure grid weights for responsive design
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_styles(self):
        """Configure modern styling."""
        self.style = ttk.Style()
        
        # Configure modern theme
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
            self.style.theme_use('clam')
        elif 'alt' in available_themes:
            self.style.theme_use('alt')
        else:
            self.style.theme_use(available_themes[0])
        
        # Custom colors
        self.colors = {
            'primary': '#2563eb',      # Blue
            'primary_dark': '#1d4ed8',
            'secondary': '#10b981',    # Green
            'danger': '#ef4444',       # Red
            'warning': '#f59e0b',      # Orange
            'light': '#f8fafc',
            'dark': '#1e293b',
            'gray': '#64748b'
        }
        
        # Configure styles with error handling
        try:
            self.style.configure('Header.TLabel', 
                               font=('Segoe UI', 28, 'bold'),
                               foreground=self.colors['dark'])
            
            self.style.configure('Subheader.TLabel',
                               font=('Segoe UI', 14, 'bold'),
                               foreground=self.colors['gray'])
            
            self.style.configure('Primary.TButton',
                               font=('Segoe UI', 12, 'bold'),
                               padding=(25, 12))
            
            self.style.configure('Secondary.TButton',
                               font=('Segoe UI', 11),
                               padding=(20, 10))
            
            # Configure progress bar
            self.style.configure('Modern.Horizontal.TProgressbar',
                               background=self.colors['primary'],
                               troughcolor=self.colors['light'],
                               lightcolor=self.colors['primary'],
                               darkcolor=self.colors['primary'])
        except Exception as e:
            print(f"Warning: Could not configure all styles: {e}")
        
    def setup_variables(self):
        """Initialize variables."""
        self.current_folder = tk.StringVar()
        self.baseline_folder = tk.StringVar()
        self.output_folder = tk.StringVar(value="output")
        
        # Vendor selection variables
        self.vendor_mode = tk.StringVar(value="auto")  # auto or manual
        self.selected_vendor = tk.StringVar()
        
        # Options
        self.skip_connectivity = tk.BooleanVar(value=True)
        self.generate_pdf = tk.BooleanVar(value=True)
        self.generate_dashboard = tk.BooleanVar(value=True)
        self.parallel_processing = tk.BooleanVar(value=True)
        
        # Enhanced reporting options
        self.generate_enhanced_pdf = tk.BooleanVar(value=True)
        self.generate_enhanced_dashboard = tk.BooleanVar(value=True)
        self.include_remediation_plan = tk.BooleanVar(value=True)
        self.detailed_explanations = tk.BooleanVar(value=True)
        
        # Status and detection
        self.progress_text = tk.StringVar(value="Ready to start compliance check")
        self.progress_value = tk.DoubleVar()
        self.detected_info = tk.StringVar(value="No configuration analyzed yet")
        
        # Workers setting
        self.workers_var = tk.IntVar(value=4)
        
        # Settings variables
        if self.vendor_support:
            self.auto_detect_enabled = tk.BooleanVar(value=True)
            self.show_vendor_details = tk.BooleanVar(value=True)
            self.vendor_specific_remediation = tk.BooleanVar(value=True)
        
        self.auto_pdf = tk.BooleanVar(value=True)
        self.auto_dashboard = tk.BooleanVar(value=True)
        self.auto_remediation = tk.BooleanVar(value=False)

    def create_scrollable_frame(self, parent):
        """Create a scrollable frame with canvas and scrollbar."""
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Bind mousewheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        return scrollable_frame

    def create_widgets(self):
        """Create and arrange all widgets."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="30")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Header section
        self.create_header(main_frame)
        
        # Content notebook
        self.create_notebook(main_frame)
        
        # Status bar
        self.create_status_bar(main_frame)

    def create_header(self, parent):
        """Create header section."""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 30))
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(header_frame, text="CMMC 2.0 Compliance Tool", 
                               style='Header.TLabel')
        title_label.grid(row=0, column=0, sticky="w")
        
        # Subtitle with feature indicators
        subtitle_text = "Network Device Configuration Compliance Checker"
        features = []
        if self.vendor_support:
            features.append("Multi-Vendor Support")
        if self.enhanced_reporting:
            features.append("Enhanced Reporting")
        else:
            features.append("Basic Mode")
        
        if features:
            subtitle_text += " • " + " • ".join(features)
            
        subtitle_label = ttk.Label(header_frame, 
                                  text=subtitle_text,
                                  style='Subheader.TLabel')
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
    def create_notebook(self, parent):
        """Create main content notebook with scrollable tabs."""
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        
        # Compliance Check Tab
        check_tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(check_tab_frame, text="  Compliance Check  ")
        self.check_frame = self.create_scrollable_frame(check_tab_frame)
        self.create_check_tab()
        
        # Results Tab
        results_tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_tab_frame, text="  Results & Reports  ")
        self.results_frame = self.create_scrollable_frame(results_tab_frame)
        self.create_results_tab()
        
        # Enhanced Reporting Tab (if available)
        if self.enhanced_reporting:
            enhanced_tab_frame = ttk.Frame(self.notebook)
            self.notebook.add(enhanced_tab_frame, text="  Enhanced Reports  ")
            self.enhanced_frame = self.create_scrollable_frame(enhanced_tab_frame)
            self.create_enhanced_reporting_tab()
        
        # Settings Tab
        settings_tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_tab_frame, text="  Settings  ")
        self.settings_frame = self.create_scrollable_frame(settings_tab_frame)
        self.create_settings_tab()
        
        # Vendor Info Tab (if vendor support available)
        if self.vendor_support:
            vendor_tab_frame = ttk.Frame(self.notebook)
            self.notebook.add(vendor_tab_frame, text="  Vendor Info  ")
            self.vendor_frame = self.create_scrollable_frame(vendor_tab_frame)
            self.create_vendor_tab()
    
    def create_status_bar(self, parent):
        """Create status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=2, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)
        
        separator = ttk.Separator(status_frame, orient='horizontal')
        separator.grid(row=0, column=0, sticky="ew", pady=(10, 0))
        
        status_content = ttk.Frame(status_frame)
        status_content.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        status_content.grid_columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(status_content, text="Ready", 
                                     font=('Segoe UI', 9),
                                     foreground=self.colors['gray'])
        self.status_label.pack(side="left")
        
        # Version info
        version_text = "CMMC Tool v2.0"
        features = []
        if self.vendor_support:
            features.append("Multi-Vendor")
        if self.enhanced_reporting:
            features.append("Enhanced Reports")
        
        if features:
            version_text += " • " + " • ".join(features)
        
        ttk.Label(status_content, text=version_text,
                 font=('Segoe UI', 9),
                 foreground=self.colors['gray']).pack(side="right")

    def create_check_tab(self):
        """Create compliance check tab."""
        # Add padding to the scrollable frame
        main_content = ttk.Frame(self.check_frame, padding="20")
        main_content.pack(fill="both", expand=True)
        
        # File selection section
        files_frame = ttk.LabelFrame(main_content, text="Configuration Files", padding="15")
        files_frame.pack(fill="x", pady=(0, 20))
        
        # Current configs
        ttk.Label(files_frame, text="Current Configs:", font=('Segoe UI', 11, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        current_frame = ttk.Frame(files_frame)
        current_frame.pack(fill="x", pady=(0, 15))
        
        current_entry = ttk.Entry(current_frame, textvariable=self.current_folder, 
                                 font=('Segoe UI', 10), width=60)
        current_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(current_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.current_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Baseline configs
        ttk.Label(files_frame, text="Baseline Configs:", font=('Segoe UI', 11, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        baseline_frame = ttk.Frame(files_frame)
        baseline_frame.pack(fill="x", pady=(0, 15))
        
        baseline_entry = ttk.Entry(baseline_frame, textvariable=self.baseline_folder,
                                  font=('Segoe UI', 10), width=60)
        baseline_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(baseline_frame, text="Browse",
                  command=lambda: self.browse_folder(self.baseline_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Output folder
        ttk.Label(files_frame, text="Output Folder:", font=('Segoe UI', 11, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        output_frame = ttk.Frame(files_frame)
        output_frame.pack(fill="x")
        
        output_entry = ttk.Entry(output_frame, textvariable=self.output_folder,
                                font=('Segoe UI', 10), width=60)
        output_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(output_frame, text="Browse",
                  command=lambda: self.browse_folder(self.output_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Quick setup button
        quick_frame = ttk.Frame(main_content)
        quick_frame.pack(fill="x", pady=(0, 20))
        
        mock_button = ttk.Button(quick_frame, text="🚀 Use Mock Environment", 
                                style='Secondary.TButton',
                                command=self.setup_mock_environment)
        mock_button.pack(side="left")
        
        ttk.Label(quick_frame, text="(Sets up demo configs automatically)",
                 foreground=self.colors['gray']).pack(side="left", padx=(10, 0))
        
        # Processing Options section
        options_frame = ttk.LabelFrame(main_content, text="Processing Options", padding="15")
        options_frame.pack(fill="x", pady=(0, 20))
        
        options_grid = ttk.Frame(options_frame)
        options_grid.pack(fill="x")
        
        # First row of options
        option_row1 = ttk.Frame(options_grid)
        option_row1.pack(fill="x", pady=2)
        
        ttk.Checkbutton(option_row1, text="Skip TACACS connectivity test", 
                       variable=self.skip_connectivity).pack(side="left")
        
        ttk.Checkbutton(option_row1, text="Enable parallel processing", 
                       variable=self.parallel_processing).pack(side="left", padx=(30, 0))
        
        # Second row of options
        option_row2 = ttk.Frame(options_grid)
        option_row2.pack(fill="x", pady=2)
        
        if self.enhanced_reporting:
            ttk.Checkbutton(option_row2, text="Generate enhanced PDF report", 
                           variable=self.generate_enhanced_pdf).pack(side="left")
            
            ttk.Checkbutton(option_row2, text="Generate enhanced dashboard", 
                           variable=self.generate_enhanced_dashboard).pack(side="left", padx=(30, 0))
        else:
            ttk.Checkbutton(option_row2, text="Generate basic PDF report", 
                           variable=self.generate_pdf).pack(side="left")
            
            ttk.Checkbutton(option_row2, text="Generate basic dashboard", 
                           variable=self.generate_dashboard).pack(side="left", padx=(30, 0))
        
        # Third row for enhanced options
        if self.enhanced_reporting:
            option_row3 = ttk.Frame(options_grid)
            option_row3.pack(fill="x", pady=2)
            
            ttk.Checkbutton(option_row3, text="Include detailed remediation plans", 
                           variable=self.include_remediation_plan).pack(side="left")
            
            ttk.Checkbutton(option_row3, text="Include CMMC control explanations", 
                           variable=self.detailed_explanations).pack(side="left", padx=(30, 0))
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_content, text="Progress", padding="15")
        progress_frame.pack(fill="x", pady=(0, 20))
        
        # Progress text
        progress_label = ttk.Label(progress_frame, textvariable=self.progress_text,
                                  font=('Segoe UI', 11))
        progress_label.pack(anchor="w", pady=(0, 10))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          variable=self.progress_value,
                                          style='Modern.Horizontal.TProgressbar',
                                          mode='determinate')
        self.progress_bar.pack(fill="x")
        
        # Action buttons
        button_frame = ttk.Frame(main_content)
        button_frame.pack(fill="x", pady=(20, 0))
        
        self.start_button = ttk.Button(button_frame, text="🚀 Start Compliance Check",
                                      style='Primary.TButton',
                                      command=self.start_compliance_check)
        self.start_button.pack(side="left", padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop",
                                     style='Secondary.TButton',
                                     state='disabled',
                                     command=self.stop_compliance_check)
        self.stop_button.pack(side="left", padx=(0, 10))
        
        ttk.Button(button_frame, text="📁 Open Output Folder",
                  command=self.open_output_folder,
                  style='Secondary.TButton').pack(side="right")

    def create_results_tab(self):
        """Create results and reports tab."""
        # Add padding to the scrollable frame
        main_content = ttk.Frame(self.results_frame, padding="20")
        main_content.pack(fill="both", expand=True)
        
        # Results summary
        summary_frame = ttk.LabelFrame(main_content, text="Latest Results", padding="15")
        summary_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        # Create scrollable text widget
        text_frame = ttk.Frame(summary_frame)
        text_frame.pack(fill="both", expand=True)
        
        self.summary_text = tk.Text(text_frame, height=10, wrap=tk.WORD,
                                   font=('Consolas', 10), state='disabled')
        
        # Add scrollbar to text widget
        text_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.summary_text.pack(side="left", fill="both", expand=True)
        text_scrollbar.pack(side="right", fill="y")
        
        # Report generation
        reports_frame = ttk.LabelFrame(main_content, text="Generate Reports", padding="15")
        reports_frame.pack(fill="x", pady=(0, 20))
        
        reports_buttons = ttk.Frame(reports_frame)
        reports_buttons.pack(fill="x")
        
        if self.enhanced_reporting:
            ttk.Button(reports_buttons, text="📊 Enhanced PDF Report",
                      command=self.generate_enhanced_pdf_report,
                      style='Primary.TButton').pack(side="left", padx=(0, 10))
            
            ttk.Button(reports_buttons, text="🌐 Enhanced Dashboard",
                      command=self.generate_enhanced_dashboard_report,
                      style='Primary.TButton').pack(side="left", padx=(0, 10))
        else:
            ttk.Button(reports_buttons, text="📊 Generate PDF Report",
                      command=self.generate_pdf_report,
                      style='Primary.TButton').pack(side="left", padx=(0, 10))
            
            ttk.Button(reports_buttons, text="🌐 Generate Dashboard",
                      command=self.generate_dashboard_report,
                      style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(reports_buttons, text="🔧 Generate Remediation",
                  command=self.generate_remediation,
                  style='Secondary.TButton').pack(side="left")
        
        # Quick actions
        actions_frame = ttk.LabelFrame(main_content, text="Quick Actions", padding="15")
        actions_frame.pack(fill="x")
        
        actions_buttons = ttk.Frame(actions_frame)
        actions_buttons.pack(fill="x")
        
        ttk.Button(actions_buttons, text="📈 View Dashboard",
                  command=self.view_dashboard,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_buttons, text="📄 View Latest Report",
                  command=self.view_latest_report,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_buttons, text="📋 Export Results",
                  command=self.export_results,
                  style='Secondary.TButton').pack(side="left")
    
    def create_enhanced_reporting_tab(self):
        """Create enhanced reporting tab (only if enhanced reporting is available)."""
        if not self.enhanced_reporting:
            return
        
        # Add padding to the scrollable frame
        main_content = ttk.Frame(self.enhanced_frame, padding="20")
        main_content.pack(fill="both", expand=True)
        
        # Enhanced reporting info
        info_frame = ttk.LabelFrame(main_content, text="Enhanced Reporting Features", padding="15")
        info_frame.pack(fill="x", pady=(0, 20))
        
        info_text = tk.Text(info_frame, height=8, wrap=tk.WORD, font=('Segoe UI', 10))
        info_content = """🎯 ENHANCED REPORTING CAPABILITIES:

📊 Comprehensive PDF Reports:
• Executive summary with business impact analysis
• Detailed CMMC control explanations and implementation guidance
• Device-specific findings with remediation recommendations
• Risk assessment and compliance trends

🌐 Interactive HTML Dashboards:
• Modern, responsive design with real-time data visualization
• Detailed CMMC control explanations with implementation steps
• Interactive compliance charts and risk assessments
• Click-through navigation for detailed control information

🔧 Advanced Features:
• Detailed remediation plans with prioritized actions
• Business impact assessment and regulatory compliance status
• Resource requirements and implementation timelines
• Technical implementation guidance and best practices"""

        info_text.insert(1.0, info_content)
        info_text.config(state='disabled')
        info_text.pack(fill="both", expand=True)
        
        # Enhanced report options
        options_frame = ttk.LabelFrame(main_content, text="Report Configuration", padding="15")
        options_frame.pack(fill="x", pady=(0, 20))
        
        # Report type selection
        type_frame = ttk.Frame(options_frame)
        type_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(type_frame, text="Report Type:", font=('Segoe UI', 10, 'bold')).pack(side="left")
        
        self.report_type = tk.StringVar(value="both")
        ttk.Radiobutton(type_frame, text="PDF Only", variable=self.report_type, 
                       value="pdf").pack(side="left", padx=(20, 10))
        ttk.Radiobutton(type_frame, text="Dashboard Only", variable=self.report_type, 
                       value="dashboard").pack(side="left", padx=(10, 10))
        ttk.Radiobutton(type_frame, text="Both", variable=self.report_type, 
                       value="both").pack(side="left", padx=(10, 0))
        
        # Detail level selection
        detail_frame = ttk.Frame(options_frame)
        detail_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(detail_frame, text="Detail Level:", font=('Segoe UI', 10, 'bold')).pack(side="left")
        
        self.detail_level = tk.StringVar(value="comprehensive")
        ttk.Radiobutton(detail_frame, text="Executive Summary", variable=self.detail_level, 
                       value="executive").pack(side="left", padx=(20, 10))
        ttk.Radiobutton(detail_frame, text="Standard", variable=self.detail_level, 
                       value="standard").pack(side="left", padx=(10, 10))
        ttk.Radiobutton(detail_frame, text="Comprehensive", variable=self.detail_level, 
                       value="comprehensive").pack(side="left", padx=(10, 0))
        
        # Additional options
        additional_frame = ttk.Frame(options_frame)
        additional_frame.pack(fill="x")
        
        ttk.Checkbutton(additional_frame, text="Include technical implementation guidance", 
                       variable=self.detailed_explanations).pack(anchor="w", pady=2)
        ttk.Checkbutton(additional_frame, text="Include remediation timelines and costs", 
                       variable=self.include_remediation_plan).pack(anchor="w", pady=2)
        
        # Generate buttons
        generate_frame = ttk.LabelFrame(main_content, text="Generate Enhanced Reports", padding="15")
        generate_frame.pack(fill="x")
        
        buttons_frame = ttk.Frame(generate_frame)
        buttons_frame.pack(fill="x")
        
        ttk.Button(buttons_frame, text="📊 Generate Enhanced PDF",
                  command=self.generate_enhanced_pdf_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(buttons_frame, text="🌐 Generate Enhanced Dashboard",
                  command=self.generate_enhanced_dashboard_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(buttons_frame, text="📋 Generate Complete Report Package",
                  command=self.generate_complete_report_package,
                  style='Secondary.TButton').pack(side="right")

    def create_settings_tab(self):
        """Create settings tab."""
        main_content = ttk.Frame(self.settings_frame, padding="20")
        main_content.pack(fill="both", expand=True)
        
        # Performance settings
        perf_frame = ttk.LabelFrame(main_content, text="Performance", padding="15")
        perf_frame.pack(fill="x", pady=(0, 20))
        
        perf_content = ttk.Frame(perf_frame)
        perf_content.pack(fill="x")
        
        ttk.Label(perf_content, text="Max parallel workers:").pack(side="left", pady=5)
        workers_spinbox = ttk.Spinbox(perf_content, from_=1, to=16, textvariable=self.workers_var, width=10)
        workers_spinbox.pack(side="left", padx=(10, 0), pady=5)
        
        # Report settings
        report_frame = ttk.LabelFrame(main_content, text="Default Reports", padding="15")
        report_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(report_frame, text="Auto-generate:").pack(anchor="w", pady=5)
        
        if self.enhanced_reporting:
            ttk.Checkbutton(report_frame, text="Enhanced PDF Report", 
                           variable=self.generate_enhanced_pdf).pack(anchor="w", pady=2)
            ttk.Checkbutton(report_frame, text="Enhanced HTML Dashboard", 
                           variable=self.generate_enhanced_dashboard).pack(anchor="w", pady=2)
        else:
            ttk.Checkbutton(report_frame, text="Basic PDF Report", variable=self.auto_pdf).pack(
                anchor="w", pady=2)
            ttk.Checkbutton(report_frame, text="Basic HTML Dashboard", variable=self.auto_dashboard).pack(
                anchor="w", pady=2)
        
        ttk.Checkbutton(report_frame, text="Remediation Scripts", variable=self.auto_remediation).pack(
            anchor="w", pady=2)
        
        # Enhanced features settings (if available)
        if self.enhanced_reporting:
            enhanced_frame = ttk.LabelFrame(main_content, text="Enhanced Features", padding="15")
            enhanced_frame.pack(fill="x", pady=(0, 20))
            
            ttk.Checkbutton(enhanced_frame, text="Include detailed CMMC explanations by default", 
                           variable=self.detailed_explanations).pack(anchor="w", pady=2)
            ttk.Checkbutton(enhanced_frame, text="Include remediation plans by default", 
                           variable=self.include_remediation_plan).pack(anchor="w", pady=2)
        
        # Demo section
        demo_frame = ttk.LabelFrame(main_content, text="Demo & Testing", padding="15")
        demo_frame.pack(fill="x")
        
        ttk.Button(demo_frame, text="🔧 Create Mock Environment",
                  command=self.create_mock_environment,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="🧪 Run Test Suite",
                  command=self.run_test_suite,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="📋 View System Information",
                  command=self.show_system_info,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
    
    def create_vendor_tab(self):
        """Create vendor information and capabilities tab."""
        if not self.vendor_support:
            return
        
        # Add padding to the scrollable frame
        main_content = ttk.Frame(self.vendor_frame, padding="20")
        main_content.pack(fill="both", expand=True)
            
        # Supported vendors section
        vendors_frame = ttk.LabelFrame(main_content, text="Supported Vendors", padding="15")
        vendors_frame.pack(fill="x", pady=(0, 20))
        
        # Create scrollable text widget
        vendors_text_frame = ttk.Frame(vendors_frame)
        vendors_text_frame.pack(fill="x")
        
        vendors_text = tk.Text(vendors_text_frame, height=10, wrap=tk.WORD, font=('Consolas', 10))
        
        # Add scrollbar to vendor text
        vendors_scrollbar = ttk.Scrollbar(vendors_text_frame, orient="vertical", command=vendors_text.yview)
        vendors_text.configure(yscrollcommand=vendors_scrollbar.set)
        
        vendors_text.pack(side="left", fill="both", expand=True)
        vendors_scrollbar.pack(side="right", fill="y")
        
        # Populate with vendor information
        vendor_info = """🏢 SUPPORTED NETWORK VENDORS:

• Cisco IOS/IOS-XE    - Traditional routers & switches (15.x, 16.x, 17.x)
• Cisco IOS-XR        - Service provider routers (6.x, 7.x)  
• Arista EOS          - Data center switches (4.x)
• Juniper Junos       - Enterprise equipment (20.x, 21.x)
• Generic/Other       - Basic checks for unsupported vendors

🔍 DETECTION CAPABILITIES:
• Automatic vendor identification from configuration syntax
• Version detection for compliance rule variations
• Platform-specific command recognition
• Intelligent scoring for ambiguous configurations

🛠️ VENDOR-SPECIFIC FEATURES:
• Platform-appropriate compliance rules
• Syntax-aware configuration parsing  
• Targeted remediation command generation
• Version-specific feature support

📋 COMPLIANCE MAPPING:
• Vendor-specific control implementations
• Platform-appropriate security baselines
• Customized remediation procedures
• Industry best practices integration"""

        vendors_text.insert(1.0, vendor_info)
        vendors_text.config(state='disabled')

    # Event handlers and methods
    def browse_folder(self, var):
        """Browse for folder and set variable."""
        try:
            folder = filedialog.askdirectory(title="Select Folder")
            if folder:
                var.set(folder)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to browse folder: {e}")
    
    def setup_mock_environment(self):
        """Set up mock environment quickly."""
        try:
            mock_dir = Path("mock_configs")
            if mock_dir.exists():
                current_path = mock_dir / "current"
                baseline_path = mock_dir / "baseline"
                
                if current_path.exists() and baseline_path.exists():
                    self.current_folder.set(str(current_path.absolute()))
                    self.baseline_folder.set(str(baseline_path.absolute()))
                    self.root.update()
                    
                    messagebox.showinfo("Success", 
                                      f"Mock environment configured!\n\n"
                                      f"Current Configs: {current_path}\n"
                                      f"Baseline Configs: {baseline_path}\n\n"
                                      f"Ready to run compliance check.")
                    return
            
            # Need to create mock environment
            if messagebox.askyesno("Create Mock Environment", 
                                 "Mock environment not found. Create it now?"):
                self.create_mock_environment()
                
        except Exception as e:
            messagebox.showerror("Error", f"Mock environment setup failed: {e}")
    
    def create_mock_environment(self):
        """Create mock environment by importing from separate module."""
        try:
            from create_mock_configs import create_mock_configs
            if create_mock_configs():
                messagebox.showinfo("Success", "Mock environment created successfully!")
                self.setup_mock_environment()  # Now configure the paths
            else:
                messagebox.showerror("Error", "Failed to create mock environment")
        except ImportError:
            messagebox.showerror("Error", "Mock config creator not found. Please ensure create_mock_configs.py exists.")
        except Exception as e:
            messagebox.showerror("Error", f"Error creating mock environment: {e}")
    
    def start_compliance_check(self):
        """Start compliance check in background thread."""
        print("🚀 Start compliance check called!")
        
        # Validate inputs
        if not self.current_folder.get():
            messagebox.showerror("Error", "Please select the current configurations folder.")
            return
        
        current_path = Path(self.current_folder.get())
        if not current_path.exists():
            messagebox.showerror("Error", f"Current configs folder does not exist: {current_path}")
            return
        
        # Find config files
        config_files = list(current_path.glob("*.cfg"))
        if not config_files:
            messagebox.showerror("Error", f"No .cfg files found in: {current_path}")
            return
        
        print(f"🔍 Found {len(config_files)} config files")
        
        # Prepare for processing
        self.processing = True
        self.stop_requested = False
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_value.set(0)
        self.progress_text.set("Starting compliance check...")
        
        # Start processing in background thread
        def run_compliance_check():
            try:
                print("🔄 Background compliance check started")
                baseline_path = Path(self.baseline_folder.get()) if self.baseline_folder.get() else None
                output_path = Path(self.output_folder.get())
                output_path.mkdir(exist_ok=True)
                
                results = []
                total_files = len(config_files)
                
                for i, config_file in enumerate(config_files):
                    if self.stop_requested:
                        print("⏹ Stop requested, breaking out of loop")
                        break
                    
                    print(f"🔍 Processing {config_file.name} ({i+1}/{total_files})")
                    
                    # Update progress
                    progress = int((i / total_files) * 100)
                    self.root.after(0, lambda p=progress: self.progress_value.set(p))
                    self.root.after(0, lambda f=config_file.name: self.progress_text.set(f"Checking {f}..."))
                    
                    # Find corresponding baseline file
                    baseline_file = None
                    if baseline_path and baseline_path.exists():
                        baseline_file = baseline_path / config_file.name
                        if not baseline_file.exists():
                            baseline_file = None
                    
                    # Run compliance check
                    result = self.compliance_checker.check_config_compliance(
                        str(config_file),
                        str(baseline_file) if baseline_file else None,
                        skip_connectivity=self.skip_connectivity.get()
                    )
                    
                    results.append(result)
                    print(f"✅ {result['hostname']}: {result['score']}% compliant")
                
                # Save results to CSV
                csv_file = output_path / "compliance_results.csv"
                self.save_results_to_csv(results, csv_file)
                
                # Store results for enhanced dashboard generation
                self.latest_results = results
                
                # Complete
                if not self.stop_requested:
                    self.root.after(0, lambda: self.compliance_check_complete(results))
                else:
                    self.root.after(0, lambda: self.compliance_check_stopped())
                    
            except Exception as e:
                print(f"❌ Error in compliance check: {e}")
                import traceback
                traceback.print_exc()
                self.root.after(0, lambda: self.compliance_check_error(str(e)))
        
        # Start background thread
        thread = threading.Thread(target=run_compliance_check, daemon=True)
        thread.start()
        
        print("✅ Compliance check thread started")

    def save_results_to_csv(self, results, csv_file):
        """Save compliance results to CSV file."""
        try:
            print(f"💾 Saving results to: {csv_file}")
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'hostname', 'file_path', 'vendor_display', 'score', 
                    'compliant', 'total_controls', 'passed_controls', 'issues'
                ])
                
                # Write data
                for result in results:
                    passed_controls = sum(1 for check in result.get('checks', {}).values() if check.get('passed', False))
                    total_controls = len(result.get('checks', {}))
                    issues_text = '; '.join(result.get('issues', []))
                    
                    writer.writerow([
                        result.get('hostname', 'Unknown'),
                        result.get('file_path', ''),
                        result.get('vendor_display', 'Unknown'),
                        result.get('score', 0),
                        result.get('compliant', False),
                        total_controls,
                        passed_controls,
                        issues_text
                    ])
            
            print(f"✅ Results saved to CSV: {csv_file}")
            
        except Exception as e:
            print(f"❌ Error saving CSV: {e}")
    
    def compliance_check_complete(self, results):
        """Handle completion of compliance check."""
        print(f"🎉 Compliance check complete! Processed {len(results)} files")
        
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_value.set(100)
        
        if results:
            compliant = sum(1 for r in results if r.get('compliant', False))
            total = len(results)
            
            self.progress_text.set(f"Complete! {compliant}/{total} devices compliant")
            self.update_status("Compliance check completed")
            
            # Update results summary
            self.update_results_summary(results)
            
            # Generate reports if enabled
            if self.enhanced_reporting:
                if self.generate_enhanced_pdf.get():
                    print("📊 Auto-generating enhanced PDF report...")
                    self.root.after(1000, lambda: self.generate_enhanced_pdf_report(results))
                
                if self.generate_enhanced_dashboard.get():
                    print("🌐 Auto-generating enhanced dashboard...")
                    self.root.after(1500, lambda: self.generate_enhanced_dashboard_report(results))
            else:
                if self.generate_pdf.get():
                    print("📊 Auto-generating basic PDF report...")
                    self.root.after(1000, self.generate_pdf_report)
                
                if self.generate_dashboard.get():
                    print("🌐 Auto-generating basic dashboard...")
                    self.root.after(1500, self.generate_dashboard_report)
            
            # Switch to results tab
            self.notebook.select(1)
            
            # Enhanced completion message with vendor info
            vendor_info = ""
            if results:
                vendor_types = set()
                for result in results:
                    if 'vendor_display' in result:
                        vendor_types.add(result['vendor_display'])
                if vendor_types:
                    vendor_info = f"\nVendors detected: {', '.join(vendor_types)}"
            
            features_used = []
            if self.enhanced_reporting:
                features_used.append("enhanced reporting")
            if self.vendor_support:
                features_used.append("multi-vendor analysis")
            
            features_text = f"\nFeatures: {', '.join(features_used)}" if features_used else ""
            
            messagebox.showinfo("Complete", 
                              f"Compliance check complete!\n"
                              f"Processed: {total} devices\n"
                              f"Compliant: {compliant} devices\n"
                              f"Compliance rate: {(compliant/total*100):.1f}%{vendor_info}{features_text}\n"
                              f"Results saved to: {self.output_folder.get()}")
        else:
            self.progress_text.set("Complete! No results to process")
            self.update_status("Compliance check completed (no results)")
            messagebox.showinfo("Complete", "Compliance check completed but no results were generated.")
    
    def compliance_check_stopped(self):
        """Handle stopped compliance check."""
        print("⏹ Compliance check stopped by user")
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_text.set("Stopped by user")
        self.update_status("Stopped")
    
    def compliance_check_error(self, error_message):
        """Handle compliance check error."""
        print(f"❌ Compliance check error: {error_message}")
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_text.set("Error occurred")
        self.update_status("Error")
        messagebox.showerror("Error", f"Compliance check failed: {error_message}")
    
    def stop_compliance_check(self):
        """Stop compliance check."""
        print("⏹ Stop button clicked")
        self.stop_requested = True
        self.stop_button.config(state='disabled')
        self.progress_text.set("Stopping...")

    def update_results_summary(self, results):
        """Update results summary display with vendor information."""
        if not hasattr(self, 'summary_text'):
            return
            
        print("📊 Updating results summary...")
        self.summary_text.config(state='normal')
        self.summary_text.delete(1.0, tk.END)
        
        summary = f"Compliance Check Results Summary\n"
        summary += f"{'='*50}\n"
        summary += f"Total Devices: {len(results)}\n"
        compliant = sum(1 for r in results if r.get('compliant', False))
        summary += f"Compliant: {compliant}\n"
        summary += f"Non-Compliant: {len(results) - compliant}\n"
        summary += f"Compliance Rate: {(compliant/len(results)*100):.1f}%\n\n"
        
        # Add vendor breakdown if available
        if results:
            vendor_counts = {}
            for result in results:
                vendor = result.get('vendor_display', 'Unknown')
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            
            if vendor_counts:
                summary += "Vendor Breakdown:\n"
                summary += f"{'-'*20}\n"
                for vendor, count in vendor_counts.items():
                    summary += f"{vendor}: {count} device(s)\n"
                summary += "\n"
        
        # Add feature usage summary
        if self.enhanced_reporting or self.vendor_support:
            summary += "Features Used:\n"
            summary += f"{'-'*15}\n"
            if self.enhanced_reporting:
                summary += "• Enhanced reporting with detailed CMMC explanations\n"
            if self.vendor_support:
                summary += "• Multi-vendor analysis and detection\n"
            summary += "\n"
        
        summary += "Device Details:\n"
        summary += f"{'-'*30}\n"
        
        for result in results:
            hostname = result.get('hostname', 'Unknown')
            status = "PASS" if result.get('compliant') else "FAIL"
            vendor_info = ""
            
            if 'vendor_display' in result:
                vendor_info = f" ({result['vendor_display']})"
            
            summary += f"{hostname:<20} {status}{vendor_info}\n"
            
            # Show main issues for failed devices
            if not result.get('compliant') and result.get('issues'):
                main_issues = result['issues'][:3]  # Show first 3 issues
                for issue in main_issues:
                    summary += f"  • {issue}\n"
                if len(result['issues']) > 3:
                    summary += f"  • ... and {len(result['issues']) - 3} more issues\n"
                summary += "\n"
        
        self.summary_text.insert(1.0, summary)
        self.summary_text.config(state='disabled')
        print("✅ Results summary updated")
    
    def update_status(self, message):
        """Update status bar."""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
            print(f"📊 Status: {message}")

    def generate_enhanced_pdf_report(self, results=None):
        """Generate enhanced PDF report using simple PDF reporter."""
        try:
            # FIXED: Check for SimplePDFReporter availability
            if not self.pdf_reporter_available or not self.SimplePDFReporter:
                messagebox.showinfo("PDF Reporting", 
                              "PDF reporting requires ReportLab.\n"
                              "Install with: pip install reportlab\n"
                              "Falling back to basic text report.")
                self.generate_pdf_report()
                return
            
            # Use stored results if not provided
            if results is None:
                results = self.latest_results
            
            if not results:
                messagebox.showwarning("Warning", "No compliance results found. Run a compliance check first.")
                return
            
            output_path = Path(self.output_folder.get())
            output_path.mkdir(exist_ok=True)
            
            print("📊 Generating PDF report using SimplePDFReporter...")
            
            # FIXED: Create SimplePDFReporter instance (not EnhancedPDFReporter)
            pdf_reporter = self.SimplePDFReporter()
            
            # Generate the PDF
            pdf_file = output_path / "compliance_report.pdf"
            generated_file = pdf_reporter.generate_pdf_report(results, str(pdf_file))
            
            print(f"✅ PDF report generated: {generated_file}")
            
            # Show success message and offer to open
            if messagebox.askyesno("Success", 
                                 f"PDF report generated successfully!\n\n"
                                 f"Location: {generated_file}\n\n"
                                 f"Would you like to open it now?"):
                self.open_file(str(generated_file))
            
            self.update_status("PDF report generated")
            
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to generate PDF: {e}")
    
    def generate_enhanced_dashboard_report(self, results=None):
        """Generate enhanced dashboard using the dashboard generator."""
        try:
            if not self.enhanced_reporting:
                messagebox.showinfo("Enhanced Reporting", 
                              "Enhanced dashboard requires additional dependencies.\n"
                              "Using basic dashboard generation instead.")
                self.generate_dashboard_report()
                return
            
            # Use stored results if not provided
            if results is None:
                results = self.latest_results
            
            if not results:
                messagebox.showwarning("Warning", "No compliance results found. Run a compliance check first.")
                return
            
            output_path = Path(self.output_folder.get())
            output_path.mkdir(exist_ok=True)
            
            print("🌐 Generating enhanced dashboard...")
            
            # Create enhanced dashboard instance
            dashboard_generator = self.EnhancedDashboard()
            
            # Generate the dashboard
            dashboard_file = output_path / "enhanced_compliance_dashboard.html"
            generated_file = dashboard_generator.generate_dashboard(results, str(dashboard_file))
            
            print(f"✅ Enhanced dashboard generated: {generated_file}")
            
            # Show success message and offer to open
            if messagebox.askyesno("Success", 
                                 f"Enhanced dashboard generated successfully!\n\n"
                                 f"Location: {generated_file}\n\n"
                                 f"Would you like to open it now?"):
                webbrowser.open(f"file://{Path(generated_file).absolute()}")
            
            self.update_status("Enhanced dashboard generated")
            
        except Exception as e:
            print(f"❌ Error generating enhanced dashboard: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to generate enhanced dashboard: {e}")
    
    def generate_complete_report_package(self):
        """Generate complete report package using available results."""
        try:
            if not self.latest_results:
                messagebox.showwarning("Warning", "No compliance results found. Run a compliance check first.")
                return
            
            output_path = Path(self.output_folder.get())
            output_path.mkdir(exist_ok=True)
            
            print("📋 Generating complete report package...")
            
            # Generate enhanced dashboard
            self.generate_enhanced_dashboard_report(self.latest_results)
            
            # Generate basic reports as well
            self.generate_pdf_report()
            
            # Create a summary report
            summary_file = output_path / "report_package_summary.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("CMMC 2.0 Compliance Report Package\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Generated: {Path().cwd()}\n")
                f.write(f"Total devices: {len(self.latest_results)}\n")
                compliant_count = sum(1 for r in self.latest_results if r.get('compliant', False))
                f.write(f"Compliant devices: {compliant_count}\n")
                f.write(f"Compliance rate: {(compliant_count/len(self.latest_results)*100):.1f}%\n\n")
                
                f.write("Generated Reports:\n")
                f.write("- enhanced_compliance_dashboard.html (Interactive dashboard)\n")
                f.write("- compliance_results.csv (Raw data)\n")
                f.write("- compliance_report.txt (Basic text report)\n")
                f.write("- report_package_summary.txt (This file)\n")
            
            messagebox.showinfo("Success", 
                              f"Complete report package generated!\n\n"
                              f"Location: {output_path}\n"
                              f"Files: Enhanced dashboard, CSV data, text reports")
            
        except Exception as e:
            print(f"❌ Error generating report package: {e}")
            messagebox.showerror("Error", f"Failed to generate complete report package: {e}")

    # Basic reporting methods
    def generate_pdf_report(self):
        """Generate basic PDF report (fallback when enhanced reporting not available)."""
        try:
            output_path = Path(self.output_folder.get())
            csv_file = output_path / "compliance_results.csv"
            
            if not csv_file.exists():
                messagebox.showwarning("Warning", "No compliance results found. Run a compliance check first.")
                return
            
            # Simple text report for now
            report_file = output_path / "compliance_report.txt"
            
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                results = list(reader)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("CMMC 2.0 Level 1 Compliance Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Report generated: {Path().cwd()}\n")
                f.write(f"Total devices checked: {len(results)}\n\n")
                
                compliant_count = sum(1 for r in results if r['compliant'].lower() == 'true')
                f.write(f"Compliant devices: {compliant_count}\n")
                f.write(f"Non-compliant devices: {len(results) - compliant_count}\n")
                f.write(f"Overall compliance rate: {(compliant_count/len(results)*100):.1f}%\n\n")
                
                f.write("Device Details:\n")
                f.write("-" * 30 + "\n")
                for result in results:
                    status = "COMPLIANT" if result['compliant'].lower() == 'true' else "NON-COMPLIANT"
                    f.write(f"{result['hostname']}: {status} ({result['score']}%)\n")
                    if result['issues']:
                        f.write(f"  Issues: {result['issues']}\n")
                    f.write("\n")
            
            messagebox.showinfo("Success", f"Report generated: {report_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")
    
    def generate_dashboard_report(self):
        """Generate basic HTML dashboard (fallback)."""
        try:
            output_path = Path(self.output_folder.get())
            csv_file = output_path / "compliance_results.csv"
            
            if not csv_file.exists():
                messagebox.showwarning("Warning", "No compliance results found. Run a compliance check first.")
                return
                
            # Generate simple HTML dashboard
            dashboard_file = output_path / "compliance_dashboard.html"
            
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                results = list(reader)
            
            compliant_count = sum(1 for r in results if r['compliant'].lower() == 'true')
            compliance_rate = (compliant_count / len(results)) * 100 if results else 0
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CMMC Compliance Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f8fafc; }}
        .header {{ background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; padding: 30px; border-radius: 12px; text-align: center; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }}
        .stat-number {{ font-size: 2.5rem; font-weight: bold; margin-bottom: 10px; }}
        .stat-label {{ color: #64748b; font-weight: 500; }}
        .device-list {{ margin-top: 30px; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .device-header {{ background: #f1f5f9; padding: 20px; font-weight: bold; }}
        .device {{ padding: 15px 20px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; }}
        .device:last-child {{ border-bottom: none; }}
        .compliant {{ color: #10b981; font-weight: bold; }}
        .non-compliant {{ color: #ef4444; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CMMC 2.0 Level 1 Compliance Dashboard</h1>
        <p>Network Device Configuration Compliance Report</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number" style="color: #2563eb;">{len(results)}</div>
            <div class="stat-label">Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #10b981;">{compliant_count}</div>
            <div class="stat-label">Compliant</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #ef4444;">{len(results) - compliant_count}</div>
            <div class="stat-label">Non-Compliant</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: {'#10b981' if compliance_rate >= 80 else '#f59e0b' if compliance_rate >= 60 else '#ef4444'};">{compliance_rate:.1f}%</div>
            <div class="stat-label">Compliance Rate</div>
        </div>
    </div>
    
    <div class="device-list">
        <div class="device-header">Device Compliance Details</div>
"""
            
            for result in results:
                status_class = "compliant" if result['compliant'].lower() == 'true' else "non-compliant"
                status_text = "COMPLIANT" if result['compliant'].lower() == 'true' else "NON-COMPLIANT"
                
                html_content += f"""
        <div class="device">
            <div>
                <strong>{result['hostname']}</strong> - {result['vendor_display']}
                <div style="font-size: 0.9rem; color: #64748b;">Score: {result['score']}%</div>
            </div>
            <div class="{status_class}">{status_text}</div>
        </div>
"""
            
            html_content += """
    </div>
    
    <div style="text-align: center; margin-top: 30px; color: #64748b;">
        Generated by CMMC 2.0 Compliance Tool v2.0
    </div>
</body>
</html>
"""
            
            with open(dashboard_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            messagebox.showinfo("Success", f"Dashboard generated: {dashboard_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate dashboard: {e}")

    # Utility methods
    def generate_remediation(self):
        """Generate remediation scripts."""
        messagebox.showinfo("Remediation", "Remediation feature coming soon!")
    
    def view_dashboard(self):
        """Open dashboard in browser."""
        output_path = Path(self.output_folder.get())
        
        # Try enhanced dashboard first, then basic
        dashboard_files = [
            "enhanced_compliance_dashboard.html",
            "compliance_dashboard.html"
        ]
        
        for filename in dashboard_files:
            dashboard_file = output_path / filename
            if dashboard_file.exists():
                webbrowser.open(f"file://{dashboard_file.absolute()}")
                return
        
        messagebox.showwarning("Warning", "Dashboard not found. Generate it first.")
    
    def view_latest_report(self):
        """Open latest report."""
        output_path = Path(self.output_folder.get())
        
        # Try enhanced PDF first, then basic
        report_files = [
            "compliance_report.pdf",
            "compliance_report.txt"
        ]
        
        for filename in report_files:
            report_file = output_path / filename
            if report_file.exists():
                self.open_file(str(report_file))
                return
        
        messagebox.showwarning("Warning", "Report not found. Generate it first.")
    
    def export_results(self):
        """Export results in various formats."""
        try:
            output_path = Path(self.output_folder.get())
            csv_file = output_path / "compliance_results.csv"
            
            if not csv_file.exists():
                messagebox.showwarning("Warning", "No results to export. Run a compliance check first.")
                return
            
            # Ask user for export format
            export_window = tk.Toplevel(self.root)
            export_window.title("Export Results")
            export_window.geometry("300x200")
            export_window.transient(self.root)
            export_window.grab_set()
            
            # Center the window
            export_window.update_idletasks()
            x = (export_window.winfo_screenwidth() // 2) - (export_window.winfo_width() // 2)
            y = (export_window.winfo_screenheight() // 2) - (export_window.winfo_height() // 2)
            export_window.geometry(f"+{x}+{y}")
            
            tk.Label(export_window, text="Select export format:", font=('Segoe UI', 11, 'bold')).pack(pady=20)
            
            export_format = tk.StringVar(value="csv")
            
            formats = [
                ("CSV (Spreadsheet)", "csv"),
                ("JSON (Data)", "json"),
                ("TXT (Text Report)", "txt")
            ]
            
            for text, value in formats:
                tk.Radiobutton(export_window, text=text, variable=export_format, value=value).pack(anchor="w", padx=40, pady=5)
            
            def do_export():
                try:
                    if export_format.get() == "csv":
                        # CSV already exists, just copy it
                        export_file = filedialog.asksaveasfilename(
                            defaultextension=".csv",
                            filetypes=[("CSV files", "*.csv")],
                            title="Save CSV Export"
                        )
                        if export_file:
                            import shutil
                            shutil.copy(csv_file, export_file)
                            messagebox.showinfo("Success", f"Results exported to: {export_file}")
                    
                    elif export_format.get() == "json":
                        # Convert CSV to JSON
                        export_file = filedialog.asksaveasfilename(
                            defaultextension=".json",
                            filetypes=[("JSON files", "*.json")],
                            title="Save JSON Export"
                        )
                        if export_file:
                            results = self.load_results_from_csv(csv_file)
                            with open(export_file, 'w', encoding='utf-8') as f:
                                json.dump({
                                    'compliance_results': results,
                                    'summary': {
                                        'total_devices': len(results),
                                        'compliant_devices': sum(1 for r in results if r.get('compliant', False)),
                                        'generated_by': 'CMMC 2.0 Compliance Tool v2.0'
                                    }
                                }, f, indent=2)
                            messagebox.showinfo("Success", f"Results exported to: {export_file}")
                    
                    export_window.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {e}")
            
            button_frame = tk.Frame(export_window)
            button_frame.pack(pady=20)
            
            tk.Button(button_frame, text="Export", command=do_export).pack(side="left", padx=10)
            tk.Button(button_frame, text="Cancel", command=export_window.destroy).pack(side="left", padx=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Export preparation failed: {e}")
    
    def load_results_from_csv(self, csv_file):
        """Load results from CSV file and convert to expected format."""
        results = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    result = {
                        'hostname': row.get('hostname', 'Unknown'),
                        'file_path': row.get('file_path', ''),
                        'vendor_display': row.get('vendor_display', 'Unknown'),
                        'score': int(row.get('score', 0)),
                        'compliant': row.get('compliant', 'False').lower() == 'true',
                        'issues': row.get('issues', '').split('; ') if row.get('issues') else [],
                        'checks': {}  # Would need more complex parsing for full check details
                    }
                    results.append(result)
        except Exception as e:
            print(f"Error loading results from CSV: {e}")
        
        return results
    
    def open_output_folder(self):
        """Open output folder in file explorer."""
        output_path = Path(self.output_folder.get())
        if output_path.exists():
            if sys.platform == "win32":
                os.startfile(output_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", str(output_path)])
            else:
                subprocess.run(["xdg-open", str(output_path)])
        else:
            messagebox.showwarning("Warning", f"Output folder does not exist: {output_path}")
    
    def open_file(self, file_path):
        """Open file with default application."""
        try:
            if sys.platform == "win32":
                os.startfile(file_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", file_path])
            else:
                subprocess.run(["xdg-open", file_path])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {e}")
    
    def run_test_suite(self):
        """Run the test suite."""
        try:
            messagebox.showinfo("Test Suite", 
                              "Test suite will verify:\n\n"
                              "• Core compliance checking functionality\n"
                              "• Report generation capabilities\n"
                              "• Multi-vendor support (if available)\n"
                              "• Enhanced reporting features (if available)\n\n"
                              "Feature coming soon!")
        except Exception as e:
            messagebox.showerror("Error", f"Test suite error: {e}")
    
    def show_system_info(self):
        """Show system information and feature availability."""
        try:
            info_window = tk.Toplevel(self.root)
            info_window.title("System Information")
            info_window.geometry("500x400")
            info_window.transient(self.root)
            info_window.grab_set()
            
            # Center the window
            info_window.update_idletasks()
            x = (info_window.winfo_screenwidth() // 2) - (info_window.winfo_width() // 2)
            y = (info_window.winfo_screenheight() // 2) - (info_window.winfo_height() // 2)
            info_window.geometry(f"+{x}+{y}")
            
            # Create scrollable text widget
            text_frame = tk.Frame(info_window)
            text_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            info_text = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10))
            scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=info_text.yview)
            info_text.configure(yscrollcommand=scrollbar.set)
            
            info_content = f"""CMMC 2.0 Compliance Tool - System Information
{'='*50}

Version: 2.0
Platform: {sys.platform}
Python Version: {sys.version}

FEATURE AVAILABILITY:
{'─'*30}

Core Features:
✅ Basic compliance checking
✅ Configuration analysis
✅ CSV export
✅ Basic reporting

Enhanced Features:
{'✅' if self.enhanced_reporting else '❌'} Enhanced HTML dashboards with detailed explanations
{'✅' if self.enhanced_reporting else '❌'} Interactive compliance charts and risk assessments
{'✅' if self.vendor_support else '❌'} Multi-vendor support
{'✅' if self.pdf_reporter_available else '❌'} PDF report generation
{'✅' if self.enhanced_reporting else '❌'} Business impact analysis
{'✅' if self.enhanced_reporting else '❌'} Detailed remediation plans

CMMC Controls Checked:
{'─'*25}
• AC.L1-3.1.1 - Access Control Policy
• AC.L1-3.1.2 - Account Management
• IA.L1-3.5.1 - User Identification
• IA.L1-3.5.2 - User Authentication
• SC.L1-3.13.1 - Boundary Protection
• SC.L1-3.13.5 - Public Access Point Controls
• CM.L1-3.4.1 - Configuration Management

Supported File Types:
• .cfg (Cisco configuration files)
• .conf (Generic configuration files)
• .txt (Text configuration files)

Output Formats:
• CSV (Comma-separated values)
• TXT (Plain text reports)
• HTML (Web dashboards)
{"• PDF (Professional reports)" if self.pdf_reporter_available else ""}
{"• Enhanced HTML dashboards" if self.enhanced_reporting else ""}
{"• JSON (Structured data)" if self.enhanced_reporting else ""}

INSTALLATION NOTES:
{'─'*20}
Enhanced dashboard generator is available.
{"PDF reporting (SimplePDFReporter) is available." if self.pdf_reporter_available else "For PDF reports, install: pip install reportlab"}

Current Working Directory:
{Path.cwd()}

Output Directory:
{self.output_folder.get()}
"""
            
            info_text.insert(1.0, info_content)
            info_text.config(state='disabled')
            
            info_text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Close button
            close_button = tk.Button(info_window, text="Close", command=info_window.destroy)
            close_button.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show system info: {e}")
    
    def on_closing(self):
        """Handle window closing event."""
        if self.processing:
            if messagebox.askokcancel("Quit", "A compliance check is running. Stop it and quit?"):
                self.stop_requested = True
                self.processing = False
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Start the GUI application."""
        try:
            print("🚀 Starting CMMC GUI application...")
            self.root.mainloop()
        except Exception as e:
            print(f"Error running GUI: {e}")
            messagebox.showerror("Error", f"GUI error: {e}")

def main():
    """Main entry point."""
    try:
        print("🎯 Initializing CMMC 2.0 Compliance Tool...")
        app = ModernCMMCGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")
        # Show error in a simple dialog if possible
        try:
            root = tk.Tk()
            root.withdraw()  # Hide main window
            messagebox.showerror("Startup Error", f"Failed to start CMMC GUI: {e}")
            root.destroy()
        except:
            print("Could not show error dialog")

if __name__ == "__main__":
    main()