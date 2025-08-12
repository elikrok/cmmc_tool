# modern_gui.py
"""Modern, aesthetic GUI for CMMC compliance checking with multi-vendor support."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import subprocess
import webbrowser
from pathlib import Path
import json
import os
import sys
import csv
import re

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
            'AC.1.001': {
                'name': 'Access Control Policy',
                'description': 'Limit system access to authorized users',
                'check_function': self.check_access_control
            },
            'AC.1.002': {
                'name': 'Account Management', 
                'description': 'Limit system access to authorized users',
                'check_function': self.check_account_management
            },
            'IA.1.076': {
                'name': 'User Identification',
                'description': 'Identify system users',
                'check_function': self.check_user_identification
            },
            'IA.1.077': {
                'name': 'User Authentication',
                'description': 'Authenticate system users',
                'check_function': self.check_user_authentication
            },
            'SC.1.175': {
                'name': 'Boundary Protection',
                'description': 'Monitor and control network communications',
                'check_function': self.check_boundary_protection
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
            
            for control_id, control_info in self.cmmc_controls.items():
                check_result = control_info['check_function'](config_content)
                result['checks'][control_id] = {
                    'name': control_info['name'],
                    'description': control_info['description'],
                    'passed': check_result['passed'],
                    'details': check_result['details'],
                    'issues': check_result['issues']
                }
                
                if check_result['passed']:
                    passed_controls += 1
                else:
                    result['issues'].extend(check_result['issues'])
            
            # Calculate score and compliance
            result['score'] = int((passed_controls / total_controls) * 100)
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
        """Check AC.1.001 - Access Control Policy implementation."""
        issues = []
        passed = True
        
        # Check for VTY access control
        if 'line vty' in config:
            if 'access-class' not in config:
                issues.append("VTY lines missing access-class restrictions")
                passed = False
        
        # Check for management interface protection
        if 'interface Management' in config or 'interface Vlan' in config:
            if 'ip access-group' not in config:
                issues.append("Management interfaces may lack access control")
        
        return {
            'passed': passed,
            'details': "Checks for access control lists and VTY restrictions",
            'issues': issues
        }
    
    def check_account_management(self, config):
        """Check AC.1.002 - Account Management."""
        issues = []
        passed = False
        
        # Check for local users
        if 'username ' in config:
            passed = True
        else:
            issues.append("No local user accounts found")
        
        # Check for privilege levels
        if 'privilege 15' not in config:
            issues.append("No administrative privilege accounts found")
        
        return {
            'passed': passed,
            'details': "Checks for proper user account configuration",
            'issues': issues
        }
    
    def check_user_identification(self, config):
        """Check IA.1.076 - User Identification."""
        issues = []
        passed = False
        
        if 'username ' in config:
            passed = True
        else:
            issues.append("No user identification mechanism found")
            
        return {
            'passed': passed,
            'details': "Checks for user identification systems",
            'issues': issues
        }
    
    def check_user_authentication(self, config):
        """Check IA.1.077 - User Authentication.""" 
        issues = []
        passed = True
        
        # Check for enable secret
        if 'enable secret' not in config and 'enable password' not in config:
            issues.append("Missing enable secret/password")
            passed = False
        
        # Check for AAA authentication
        if 'aaa authentication' not in config and 'username ' not in config:
            issues.append("No authentication mechanism configured")
            passed = False
        
        # Check for weak passwords (plaintext)
        if 'password ' in config and 'secret' not in config:
            issues.append("Plaintext passwords detected")
        
        return {
            'passed': passed,
            'details': "Checks for authentication mechanisms and password security",
            'issues': issues
        }
    
    def check_boundary_protection(self, config):
        """Check SC.1.175 - Boundary Protection."""
        issues = []
        passed = False
        
        # Check for access lists
        if 'ip access-list' in config or 'access-list' in config:
            passed = True
        else:
            issues.append("No access control lists found for boundary protection")
        
        # Check for interface security
        if 'interface ' in config and 'ip access-group' not in config:
            issues.append("Interfaces may lack access control groups")
        
        return {
            'passed': passed,
            'details': "Checks for network boundary protection mechanisms",
            'issues': issues
        }

class ModernCMMCGUI:
    def __init__(self):
        self.root = tk.Tk()
        
        # Initialize compliance checker
        self.compliance_checker = ComplianceChecker()
        
        # Initialize vendor support FIRST
        self.initialize_vendor_support()
        
        # Initialize processing flag early to prevent old demo timers
        self.processing = False
        self.stop_requested = False
        
        # Then setup the rest
        self.setup_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        
        print("🧹 Cancelling any existing scheduled callbacks...")
        # Cancel any pending after() calls that might exist
        try:
            # Clear all pending after() calls
            self.root.after_idle(lambda: None)
        except:
            pass
    
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
        self.root.geometry("1100x750")
        self.root.minsize(900, 650)
        
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
                               font=('Segoe UI', 24, 'bold'),
                               foreground=self.colors['dark'])
            
            self.style.configure('Subheader.TLabel',
                               font=('Segoe UI', 12, 'bold'),
                               foreground=self.colors['gray'])
            
            self.style.configure('Primary.TButton',
                               font=('Segoe UI', 11, 'bold'),
                               padding=(20, 10))
            
            self.style.configure('Secondary.TButton',
                               font=('Segoe UI', 10),
                               padding=(15, 8))
            
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
        # Create canvas and scrollbar
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
        
        # Subtitle with vendor support indicator
        subtitle_text = "Network Device Configuration Compliance Checker"
        if self.vendor_support:
            subtitle_text += " • Multi-Vendor Support Enabled"
        else:
            subtitle_text += " • Basic Mode"
            
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
        
    def create_check_tab(self):
        """Create compliance check tab."""
        # Add padding to the scrollable frame
        main_content = ttk.Frame(self.check_frame, padding="20")
        main_content.pack(fill="both", expand=True)
        
        # File selection section
        files_frame = ttk.LabelFrame(main_content, text="Configuration Files", padding="15")
        files_frame.pack(fill="x", pady=(0, 20))
        
        # Current configs
        ttk.Label(files_frame, text="Current Configs:", font=('Segoe UI', 10, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        current_frame = ttk.Frame(files_frame)
        current_frame.pack(fill="x", pady=(0, 15))
        
        current_entry = ttk.Entry(current_frame, textvariable=self.current_folder, 
                                 font=('Segoe UI', 10), width=50)
        current_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(current_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.current_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Baseline configs
        ttk.Label(files_frame, text="Baseline Configs:", font=('Segoe UI', 10, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        baseline_frame = ttk.Frame(files_frame)
        baseline_frame.pack(fill="x", pady=(0, 15))
        
        baseline_entry = ttk.Entry(baseline_frame, textvariable=self.baseline_folder,
                                  font=('Segoe UI', 10), width=50)
        baseline_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(baseline_frame, text="Browse",
                  command=lambda: self.browse_folder(self.baseline_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Output folder
        ttk.Label(files_frame, text="Output Folder:", font=('Segoe UI', 10, 'bold')).pack(
            anchor="w", pady=(0, 8))
        
        output_frame = ttk.Frame(files_frame)
        output_frame.pack(fill="x")
        
        output_entry = ttk.Entry(output_frame, textvariable=self.output_folder,
                                font=('Segoe UI', 10), width=50)
        output_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Button(output_frame, text="Browse",
                  command=lambda: self.browse_folder(self.output_folder),
                  style='Secondary.TButton').pack(side="right")
        
        # Quick setup button
        quick_frame = ttk.Frame(main_content)
        quick_frame.pack(fill="x", pady=(0, 20))
        
        # Mock environment button
        def mock_env_wrapper():
            print("🔗 Mock environment wrapper called!")
            try:
                mock_dir = Path("mock_configs")
                print(f"📁 Checking if mock_configs exists: {mock_dir.exists()}")
                
                if mock_dir.exists():
                    current_path = mock_dir / "current"
                    baseline_path = mock_dir / "baseline"
                    
                    if current_path.exists() and baseline_path.exists():
                        print(f"✅ Setting existing paths")
                        self.current_folder.set(str(current_path.absolute()))
                        self.baseline_folder.set(str(baseline_path.absolute()))
                        self.root.update()
                        
                        messagebox.showinfo("Success", 
                                          f"Mock environment configured!\n\n"
                                          f"Current Configs: {current_path}\n"
                                          f"Baseline Configs: {baseline_path}\n\n"
                                          f"Ready to run compliance check.")
                    else:
                        print("❌ Mock directories incomplete")
                        messagebox.showwarning("Warning", "Mock directories exist but are incomplete")
                else:
                    print("❌ mock_configs not found, need to create it")
                    
                    if messagebox.askyesno("Create Mock Environment", 
                                         "Mock environment not found. Create it now?\n\n"
                                         "This will create the demo configuration files."):
                        print("🔧 Creating mock environment...")
                        
                        try:
                            # First try to run the external script
                            setup_script = Path("setup_mock_environment.py")
                            if setup_script.exists():
                                print("📁 Found setup_mock_environment.py, running it...")
                                
                                # Try to run with proper encoding handling
                                try:
                                    result = subprocess.run(
                                        [sys.executable, str(setup_script)], 
                                        capture_output=True, 
                                        text=True,
                                        encoding='utf-8',
                                        errors='replace',  # Replace problematic characters
                                        cwd=os.getcwd()
                                    )
                                    
                                    if result.returncode == 0:
                                        print("✅ setup_mock_environment.py completed successfully")
                                    else:
                                        print(f"⚠️ Script returned code {result.returncode}")
                                        if result.stderr:
                                            print(f"Script error: {result.stderr}")
                                        # Continue anyway, might still have created files
                                        
                                except UnicodeError as ue:
                                    print(f"⚠️ Unicode error running script: {ue}")
                                    print("📝 Falling back to direct creation...")
                                    # Fall through to direct creation
                                    
                            else:
                                print("📝 setup_mock_environment.py not found, creating directly...")
                            
                            # Direct creation method (fallback or primary)
                            print("📁 Creating mock environment directly...")
                            self.create_mock_environment_direct()
                            
                            # Check if directories were created
                            if mock_dir.exists():
                                current_path = mock_dir / "current"
                                baseline_path = mock_dir / "baseline"
                                
                                if current_path.exists() and baseline_path.exists():
                                    self.current_folder.set(str(current_path.absolute()))
                                    self.baseline_folder.set(str(baseline_path.absolute()))
                                    self.root.update()
                                    
                                    messagebox.showinfo("Success", 
                                                      f"Mock environment created and configured!\n\n"
                                                      f"Current Configs: {current_path}\n"
                                                      f"Baseline Configs: {baseline_path}")
                                else:
                                    messagebox.showerror("Error", "Mock directories were not created properly")
                            else:
                                messagebox.showerror("Error", "Failed to create mock environment")
                                
                        except Exception as e:
                            print(f"💥 Error creating mock environment: {e}")
                            messagebox.showerror("Error", f"Failed to create mock environment: {e}")
                    else:
                        print("❌ User cancelled")
                        
            except Exception as e:
                print(f"💥 Error in wrapper: {e}")
                import traceback
                traceback.print_exc()
                messagebox.showerror("Error", f"Mock environment error: {e}")
        
        mock_button = ttk.Button(quick_frame, text="🚀 Use Mock Environment", 
                                style='Secondary.TButton',
                                command=mock_env_wrapper)
        mock_button.pack(side="left")
        
        ttk.Label(quick_frame, text="(Sets up demo configs automatically)",
                 foreground=self.colors['gray']).pack(side="left", padx=(10, 0))
        
        # Options section
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
        
        ttk.Checkbutton(option_row2, text="Generate PDF report", 
                       variable=self.generate_pdf).pack(side="left")
        
        ttk.Checkbutton(option_row2, text="Generate HTML dashboard", 
                       variable=self.generate_dashboard).pack(side="left", padx=(30, 0))
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_content, text="Progress", padding="15")
        progress_frame.pack(fill="x", pady=(0, 20))
        
        # Progress text
        progress_label = ttk.Label(progress_frame, textvariable=self.progress_text,
                                  font=('Segoe UI', 10))
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
        
        self.summary_text = tk.Text(text_frame, height=8, wrap=tk.WORD,
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
                  style='Secondary.TButton').pack(side="left")
        
    def create_settings_tab(self):
        """Create settings tab."""
        # Add padding to the scrollable frame
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
        
        ttk.Checkbutton(report_frame, text="PDF Report", variable=self.auto_pdf).pack(
            anchor="w", pady=2)
        
        ttk.Checkbutton(report_frame, text="HTML Dashboard", variable=self.auto_dashboard).pack(
            anchor="w", pady=2)
        
        ttk.Checkbutton(report_frame, text="Remediation Scripts", variable=self.auto_remediation).pack(
            anchor="w", pady=2)
        
        # Demo section
        demo_frame = ttk.LabelFrame(main_content, text="Demo & Testing", padding="15")
        demo_frame.pack(fill="x")
        
        ttk.Button(demo_frame, text="🔧 Create Mock Environment",
                  command=self.create_mock_environment,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="🧪 Run Test Suite",
                  command=self.run_test_suite,
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
        
        vendors_text = tk.Text(vendors_text_frame, height=8, wrap=tk.WORD, font=('Consolas', 10))
        
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
• Version-specific feature support"""

        vendors_text.insert(1.0, vendor_info)
        vendors_text.config(state='disabled')
    
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
        version_text = "CMMC Tool v1.0"
        if self.vendor_support:
            version_text += " • Multi-Vendor"
        
        ttk.Label(status_content, text=version_text,
                 font=('Segoe UI', 9),
                 foreground=self.colors['gray']).pack(side="right")
    
    # Event handlers
    def browse_folder(self, var):
        """Browse for folder and set variable."""
        try:
            folder = filedialog.askdirectory(title="Select Folder")
            if folder:
                var.set(folder)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to browse folder: {e}")
    
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
        
        print(f"📁 Found {len(config_files)} config files")
        
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
            if self.generate_pdf.get():
                print("📊 Auto-generating PDF report...")
                self.root.after(1000, self.generate_pdf_report)
            
            if self.generate_dashboard.get():
                print("🌐 Auto-generating dashboard...")
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
            
            messagebox.showinfo("Complete", 
                              f"Compliance check complete!\n"
                              f"Processed: {total} devices\n"
                              f"Compliant: {compliant} devices\n"
                              f"Compliance rate: {(compliant/total*100):.1f}%{vendor_info}\n"
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
    
    def generate_pdf_report(self):
        """Generate PDF report."""
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
        """Generate HTML dashboard."""
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
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CMMC Compliance Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2563eb; color: white; padding: 20px; border-radius: 8px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8fafc; padding: 15px; border-radius: 8px; flex: 1; }}
        .device-list {{ margin-top: 20px; }}
        .device {{ padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .compliant {{ background: #d1fae5; }}
        .non-compliant {{ background: #fee2e2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CMMC 2.0 Level 1 Compliance Dashboard</h1>
        <p>Network Device Configuration Compliance Report</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3>Total Devices</h3>
            <h2>{len(results)}</h2>
        </div>
        <div class="stat-card">
            <h3>Compliant</h3>
            <h2>{compliant_count}</h2>
        </div>
        <div class="stat-card">
            <h3>Non-Compliant</h3>
            <h2>{len(results) - compliant_count}</h2>
        </div>
        <div class="stat-card">
            <h3>Compliance Rate</h3>
            <h2>{compliance_rate:.1f}%</h2>
        </div>
    </div>
    
    <div class="device-list">
        <h3>Device Details</h3>
"""
            
            for result in results:
                status_class = "compliant" if result['compliant'].lower() == 'true' else "non-compliant"
                status_text = "COMPLIANT" if result['compliant'].lower() == 'true' else "NON-COMPLIANT"
                
                html_content += f"""
        <div class="device {status_class}">
            <strong>{result['hostname']}</strong> - {status_text} ({result['score']}%)
            <br>Vendor: {result['vendor_display']}
"""
                if result['issues']:
                    html_content += f"<br>Issues: {result['issues']}"
                
                html_content += "</div>\n"
            
            html_content += """
    </div>
</body>
</html>
"""
            
            with open(dashboard_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            messagebox.showinfo("Success", f"Dashboard generated: {dashboard_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate dashboard: {e}")
    
    def generate_remediation(self):
        """Generate remediation scripts."""
        messagebox.showinfo("Remediation", "Remediation feature coming soon!")
    
    def view_dashboard(self):
        """Open dashboard in browser."""
        output_path = Path(self.output_folder.get())
        dashboard_file = output_path / "compliance_dashboard.html"
        
        if dashboard_file.exists():
            webbrowser.open(f"file://{dashboard_file.absolute()}")
        else:
            messagebox.showwarning("Warning", "Dashboard not found. Generate it first.")
    
    def view_latest_report(self):
        """Open latest report."""
        output_path = Path(self.output_folder.get())
        report_file = output_path / "compliance_report.txt"
        
        if report_file.exists():
            if sys.platform == "win32":
                os.startfile(report_file)
            elif sys.platform == "darwin":
                subprocess.run(["open", str(report_file)])
            else:
                subprocess.run(["xdg-open", str(report_file)])
        else:
            messagebox.showwarning("Warning", "Report not found. Generate it first.")
    
    def create_mock_environment_direct(self):
        """Create mock environment directly without subprocess."""
        try:
            print("🏗️ Creating mock environment directly...")
            
            # Create directory structure
            base_dir = Path("mock_configs")
            current_dir = base_dir / "current"
            baseline_dir = base_dir / "baseline"
            
            current_dir.mkdir(parents=True, exist_ok=True)
            baseline_dir.mkdir(parents=True, exist_ok=True)
            
            # Current configurations (with compliance issues)
            current_configs = {
                "edge-router-01.cfg": """!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname EdgeRouter01
!
boot-start-marker
boot-end-marker
!
! Missing enable secret - COMPLIANCE ISSUE
! Missing AAA configuration - COMPLIANCE ISSUE
!
multilink bundle-name authenticated
!
crypto pki token default removal timeout 0
!
license udi pid CISCO2921/K9 sn FCZ1648C0QJ
!
redundancy
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny   ip any any
!
ip access-list extended WAN-IN
 permit tcp any host 203.0.113.1 eq 22
 permit tcp any host 203.0.113.1 eq 443
 deny   ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
 ip access-group WAN-IN in
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Connection to Core Switch
 ip address 10.1.1.1 255.255.255.0
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 shutdown
 duplex auto
 speed auto
!
router ospf 1
 log-adjacency-changes
 network 10.1.0.0 0.0.255.255 area 0
!
ip forward-protocol nd
!
no ip http server
no ip http secure-server
!
control-plane
!
line con 0
line aux 0
line vty 0 4
 login local
 transport input ssh telnet
 ! Missing access-class - COMPLIANCE ISSUE
line vty 5 15
 login local
 transport input ssh telnet
 ! Missing access-class - COMPLIANCE ISSUE
!
end""",

                "core-switch-01.cfg": """!
hostname CoreSwitch01
!
management ssh
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
username readonly privilege 1 secret readpass
!
aaa authentication login default group tacacs+ local
aaa group server tacacs+ TACACS-SERVERS
 server 10.1.100.10
 server 10.1.100.11
!
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
ip access-list extended DMZ-IN
 10 permit tcp any host 10.1.50.10 eq 80
 20 permit tcp any host 10.1.50.10 eq 443
 30 permit tcp any host 10.1.50.20 eq 25
 40 deny ip any any
!
vlan 100
 name Management
!
vlan 200
 name Users
!
vlan 300
 name Servers
!
vlan 500
 name DMZ
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Vlan100
 description Management VLAN
 ip address 10.1.100.1/24
!
interface Vlan200
 description User VLAN
 ip address 10.1.200.1/24
!
interface Vlan300
 description Server VLAN
 ip address 10.1.30.1/24
!
interface Vlan500
 description DMZ VLAN
 ip address 10.1.50.1/24
 ip access-group DMZ-IN in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,500
!
interface Ethernet2
 description User Access Port
 switchport mode access
 switchport access vlan 200
!
interface Ethernet3
 description Server Access Port
 switchport mode access
 switchport access vlan 300
!
interface Ethernet4
 description DMZ Access Port
 switchport mode access
 switchport access vlan 500
!
line vty 0 4
 login local
 transport input ssh
!
end""",

                "dmz-firewall-01.cfg": """!
hostname DMZFirewall01
!
! Missing enable secret - COMPLIANCE ISSUE
!
! Missing proper user accounts - COMPLIANCE ISSUE
username fwadmin privilege 15 password plaintext123
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key sharedkey123
tacacs-server host 10.1.100.12 key sharedkey123
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 permit tcp any host 10.1.50.20 eq 25
 permit tcp any host 10.1.50.20 eq 587
 deny ip any any
!
ip access-list extended DMZ-TO-INSIDE
 permit tcp host 10.1.50.10 10.1.30.0 0.0.0.255 eq 3306
 permit tcp host 10.1.50.20 10.1.30.0 0.0.0.255 eq 3306
 deny ip any any
!
ip access-list extended MGMT-ACCESS
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
interface GigabitEthernet0/0
 description Outside/WAN Interface
 ip address 203.0.113.50 255.255.255.0
 ip access-group OUTSIDE-IN in
!
interface GigabitEthernet0/1
 description DMZ Interface
 ip address 10.1.50.254 255.255.255.0
 ! Missing ACL - COMPLIANCE ISSUE
!
interface GigabitEthernet0/2
 description Inside Interface
 ip address 10.1.30.254 255.255.255.0
 ip access-group DMZ-TO-INSIDE in
!
router ospf 1
 network 10.1.30.0 0.0.0.255 area 0
 network 10.1.50.0 0.0.0.255 area 0
!
line vty 0 4
 login local
 transport input ssh telnet
 ! Telnet enabled - COMPLIANCE ISSUE
 access-class MGMT-ACCESS in
!
end"""
            }
            
            # Baseline configurations (compliant versions)
            baseline_configs = {
                "edge-router-01.cfg": """!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname EdgeRouter01
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$SAFE$complianthashere789
!
username admin privilege 15 secret adminpass123
username operator privilege 5 secret operatorpass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
multilink bundle-name authenticated
!
crypto pki token default removal timeout 0
!
license udi pid CISCO2921/K9 sn FCZ1648C0QJ
!
redundancy
!
ip access-list extended VTY-MGMT
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny   ip any any
!
ip access-list extended WAN-IN
 permit tcp any host 203.0.113.1 eq 22
 permit tcp any host 203.0.113.1 eq 443
 deny   ip any any
!
interface GigabitEthernet0/0
 description WAN/Internet Connection
 ip address 203.0.113.1 255.255.255.0
 ip access-group WAN-IN in
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Connection to Core Switch
 ip address 10.1.1.1 255.255.255.0
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 shutdown
 duplex auto
 speed auto
!
router ospf 1
 log-adjacency-changes
 network 10.1.0.0 0.0.255.255 area 0
!
ip forward-protocol nd
!
no ip http server
no ip http secure-server
!
control-plane
!
line con 0
line aux 0
line vty 0 4
 login local
 transport input ssh
 access-class VTY-MGMT in
line vty 5 15
 login local
 transport input ssh
 access-class VTY-MGMT in
!
end""",

                "core-switch-01.cfg": """!
hostname CoreSwitch01
!
management ssh
!
enable secret 5 $1$ABCD$hashedpasswordhere123
!
username admin privilege 15 secret adminpass123
username netops privilege 5 secret netopspass
username readonly privilege 1 secret readpass
!
aaa authentication login default group tacacs+ local
aaa group server tacacs+ TACACS-SERVERS
 server 10.1.100.10
 server 10.1.100.11
!
tacacs-server host 10.1.100.10 key supersecretkey
tacacs-server host 10.1.100.11 key supersecretkey
!
ip access-list standard MGMT-HOSTS
 10 permit 10.1.100.0 0.0.0.255
 20 deny any
!
ip access-list extended DMZ-IN
 10 permit tcp any host 10.1.50.10 eq 80
 20 permit tcp any host 10.1.50.10 eq 443
 30 permit tcp any host 10.1.50.20 eq 25
 40 deny ip any any
!
vlan 100
 name Management
!
vlan 200
 name Users
!
vlan 300
 name Servers
!
vlan 500
 name DMZ
!
interface Management1
 description Management Interface
 ip address 10.1.100.5/24
 ip access-group MGMT-HOSTS in
!
interface Vlan100
 description Management VLAN
 ip address 10.1.100.1/24
!
interface Vlan200
 description User VLAN
 ip address 10.1.200.1/24
!
interface Vlan300
 description Server VLAN
 ip address 10.1.30.1/24
!
interface Vlan500
 description DMZ VLAN
 ip address 10.1.50.1/24
 ip access-group DMZ-IN in
!
interface Ethernet1
 description Uplink to Edge Router
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,500
!
interface Ethernet2
 description User Access Port
 switchport mode access
 switchport access vlan 200
!
interface Ethernet3
 description Server Access Port
 switchport mode access
 switchport access vlan 300
!
interface Ethernet4
 description DMZ Access Port
 switchport mode access
 switchport access vlan 500
!
line vty 0 4
 login local
 transport input ssh
!
end""",

                "dmz-firewall-01.cfg": """!
hostname DMZFirewall01
!
enable secret 5 $1$WXYZ$anotherhashhere456
!
username fwadmin privilege 15 secret fwpass123
username security privilege 10 secret secpass
!
aaa authentication login default group tacacs+ local
tacacs-server host 10.1.100.10 key sharedkey123
tacacs-server host 10.1.100.12 key sharedkey123
!
ip access-list extended OUTSIDE-IN
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 permit tcp any host 10.1.50.20 eq 25
 permit tcp any host 10.1.50.20 eq 587
 deny ip any any
!
ip access-list extended DMZ-TO-INSIDE
 permit tcp host 10.1.50.10 10.1.30.0 0.0.0.255 eq 3306
 permit tcp host 10.1.50.20 10.1.30.0 0.0.0.255 eq 3306
 deny ip any any
!
ip access-list extended MGMT-ACCESS
 permit tcp 10.1.100.0 0.0.0.255 any eq 22
 deny ip any any
!
ip access-list extended DMZ-PROTECTION
 permit tcp any host 10.1.50.10 eq 80
 permit tcp any host 10.1.50.10 eq 443
 deny ip any any
!
interface GigabitEthernet0/0
 description Outside/WAN Interface
 ip address 203.0.113.50 255.255.255.0
 ip access-group OUTSIDE-IN in
!
interface GigabitEthernet0/1
 description DMZ Interface
 ip address 10.1.50.254 255.255.255.0
 ip access-group DMZ-PROTECTION in
!
interface GigabitEthernet0/2
 description Inside Interface
 ip address 10.1.30.254 255.255.255.0
 ip access-group DMZ-TO-INSIDE in
!
router ospf 1
 network 10.1.30.0 0.0.0.255 area 0
 network 10.1.50.0 0.0.0.255 area 0
!
line vty 0 4
 login local
 transport input ssh
 access-class MGMT-ACCESS in
!
end"""
            }
            
            print("📝 Writing current configuration files...")
            # Write current configuration files
            for filename, content in current_configs.items():
                file_path = current_dir / filename
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✅ Created: {file_path}")
            
            print("📝 Writing baseline configuration files...")
            # Write baseline configuration files
            for filename, content in baseline_configs.items():
                file_path = baseline_dir / filename
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✅ Created: {file_path}")
            
            print("✅ Mock environment created successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error creating mock environment: {e}")
            return False
    
    def create_mock_environment(self):
        """Create mock environment (called from settings tab)."""
        try:
            if self.create_mock_environment_direct():
                messagebox.showinfo("Success", "Mock environment created successfully!")
            else:
                messagebox.showerror("Error", "Failed to create mock environment")
        except Exception as e:
            messagebox.showerror("Error", f"Error creating mock environment: {e}")
    
    def run_test_suite(self):
        """Run the test suite."""
        messagebox.showinfo("Test Suite", "Test suite feature coming soon!")
    
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
            self.root.mainloop()
        except Exception as e:
            print(f"Error running GUI: {e}")
            messagebox.showerror("Error", f"GUI error: {e}")

def main():
    """Main entry point."""
    try:
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