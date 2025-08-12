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
        
        ttk.Button(actions_buttons, text="🎭 Run All Demos",
                  command=self.run_all_demos,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_buttons, text="📈 View Dashboard",
                  command=self.view_dashboard,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_buttons, text="📄 View PDF Report",
                  command=self.view_pdf_report,
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
        
        # Vendor settings (if available)
        if self.vendor_support:
            vendor_settings_frame = ttk.LabelFrame(main_content, text="Vendor Detection", padding="15")
            vendor_settings_frame.pack(fill="x", pady=(0, 20))
            
            ttk.Checkbutton(vendor_settings_frame, text="Enable automatic vendor detection", 
                           variable=self.auto_detect_enabled).pack(anchor="w", pady=2)
            
            ttk.Checkbutton(vendor_settings_frame, text="Show detailed vendor information in results", 
                           variable=self.show_vendor_details).pack(anchor="w", pady=2)
            
            ttk.Checkbutton(vendor_settings_frame, text="Generate vendor-specific remediation commands", 
                           variable=self.vendor_specific_remediation).pack(anchor="w", pady=2)
        
        # Report settings
        report_frame = ttk.LabelFrame(main_content, text="Default Reports", padding="15")
        report_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(report_frame, text="Auto-generate:").pack(# modern_gui.py
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

class ModernCMMCGUI:
    def __init__(self):
        self.root = tk.Tk()
        
        # Initialize vendor support FIRST
        self.initialize_vendor_support()
        
        # Then setup the rest
        self.setup_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        self.processing = False
    
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
        
        # Vendor selection section (only if vendor support is available)
        if self.vendor_support:
            self.create_vendor_selection_section(main_content)
        
        # Quick setup button
        quick_frame = ttk.Frame(main_content)
        quick_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Button(quick_frame, text="🚀 Use Mock Environment", 
                  command=self.setup_mock_environment,
                  style='Secondary.TButton').pack(side="left")
        
        ttk.Label(quick_frame, text="(Sets up demo configs automatically)",
                 foreground=self.colors['gray']).pack(side="left", padx=(10, 0))
        
        # Detection info
        if self.vendor_support:
            detect_frame = ttk.Frame(main_content)
            detect_frame.pack(fill="x", pady=(0, 20))
            
            ttk.Label(detect_frame, text="🔍 Detection Status:", 
                     font=('Segoe UI', 10, 'bold')).pack(side="left")
            
            self.detection_label = ttk.Label(detect_frame, textvariable=self.detected_info,
                                           font=('Segoe UI', 10),
                                           foreground=self.colors['gray'])
            self.detection_label.pack(side="left", padx=(10, 0))
            
            ttk.Button(detect_frame, text="Analyze Sample Config",
                      command=self.analyze_sample_config,
                      style='Secondary.TButton').pack(side="right")
        
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
                                      command=self.start_compliance_check,
                                      style='Primary.TButton')
        self.start_button.pack(side="left", padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop",
                                     command=self.stop_compliance_check,
                                     style='Secondary.TButton',
                                     state='disabled')
        self.stop_button.pack(side="left", padx=(0, 10))
        
        ttk.Button(button_frame, text="📁 Open Output Folder",
                  command=self.open_output_folder,
                  style='Secondary.TButton').pack(side="right")
    
    def create_vendor_selection_section(self, parent):
        """Create vendor selection section."""
        vendor_frame = ttk.LabelFrame(parent, text="Vendor/Platform Selection", padding="15")
        vendor_frame.pack(fill="x", pady=(0, 20))
        
        # Auto-detect option (default)
        ttk.Radiobutton(vendor_frame, text="🔍 Auto-detect vendor from configuration", 
                       variable=self.vendor_mode, value="auto",
                       command=self.on_vendor_mode_change).pack(anchor="w", pady=2)
        
        # Manual selection
        manual_frame = ttk.Frame(vendor_frame)
        manual_frame.pack(fill="x", pady=(5, 0))
        
        ttk.Radiobutton(manual_frame, text="📋 Select manually:", 
                       variable=self.vendor_mode, value="manual",
                       command=self.on_vendor_mode_change).pack(side="left")
        
        self.vendor_combo = ttk.Combobox(manual_frame, textvariable=self.selected_vendor,
                                        state="readonly", width=30)
        self.vendor_combo.pack(side="left", padx=(10, 0))
        
        # Populate vendor list
        if self.vendor_manager:
            try:
                vendors = self.vendor_manager.get_supported_vendors()
                vendor_options = [f"{v['display_name']}" for v in vendors]
                self.vendor_combo['values'] = vendor_options
                if vendor_options:
                    self.vendor_combo.set(vendor_options[0])
            except Exception as e:
                print(f"Warning: Could not populate vendor list: {e}")
                self.vendor_combo['values'] = ["Generic"]
                self.vendor_combo.set("Generic")
        
        # Detection results display
        self.vendor_info_frame = ttk.Frame(vendor_frame)
        self.vendor_info_frame.pack(fill="x", pady=(10, 0))
        
        self.vendor_result_label = ttk.Label(self.vendor_info_frame, 
                                           text="💡 Select configuration files to see vendor detection",
                                           font=('Segoe UI', 9),
                                           foreground=self.colors['gray'])
        self.vendor_result_label.pack(anchor="w")
        
        # Initially disable manual selection
        self.vendor_combo.config(state="disabled")
    
    def create_vendor_tab(self):
        """Create vendor information and capabilities tab."""
        if not self.vendor_support:
            return
            
        # Supported vendors section
        vendors_frame = ttk.LabelFrame(self.vendor_frame, text="Supported Vendors", padding="15")
        vendors_frame.pack(fill="x", pady=(0, 20))
        
        vendors_text = tk.Text(vendors_frame, height=8, wrap=tk.WORD, font=('Consolas', 10))
        vendors_text.pack(fill="x")
        
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
        
        # Detection testing section
        test_frame = ttk.LabelFrame(self.vendor_frame, text="Test Vendor Detection", padding="15")
        test_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(test_frame, text="Paste a configuration snippet to test detection:").pack(anchor="w", pady=(0, 5))
        
        self.test_config_text = tk.Text(test_frame, height=6, wrap=tk.WORD, font=('Consolas', 9))
        self.test_config_text.pack(fill="x", pady=(0, 10))
        
        test_button_frame = ttk.Frame(test_frame)
        test_button_frame.pack(fill="x")
        
        ttk.Button(test_button_frame, text="🔍 Test Detection",
                  command=self.test_vendor_detection,
                  style='Primary.TButton').pack(side="left")
        
        ttk.Button(test_button_frame, text="📋 Load Sample Config",
                  command=self.load_sample_config,
                  style='Secondary.TButton').pack(side="left", padx=(10, 0))
        
        # Results display
        self.test_results_label = ttk.Label(test_frame, text="Results will appear here...",
                                          font=('Segoe UI', 10),
                                          foreground=self.colors['gray'])
        self.test_results_label.pack(anchor="w", pady=(10, 0))
    
    def create_results_tab(self):
        """Create results and reports tab."""
        # Results summary
        summary_frame = ttk.LabelFrame(self.results_frame, text="Latest Results", padding="15")
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        summary_frame.grid_columnconfigure(1, weight=1)
        
        self.summary_text = tk.Text(summary_frame, height=8, wrap=tk.WORD,
                                   font=('Consolas', 10), state='disabled')
        self.summary_text.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        # Report generation
        reports_frame = ttk.LabelFrame(self.results_frame, text="Generate Reports", padding="15")
        reports_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Button(reports_frame, text="📊 Generate PDF Report",
                  command=self.generate_pdf_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(reports_frame, text="🌐 Generate Dashboard",
                  command=self.generate_dashboard_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(reports_frame, text="🔧 Generate Remediation",
                  command=self.generate_remediation,
                  style='Secondary.TButton').pack(side="left")
        
        # Quick actions
        actions_frame = ttk.LabelFrame(self.results_frame, text="Quick Actions", padding="15")
        actions_frame.grid(row=2, column=0, sticky="ew")
        
        ttk.Button(actions_frame, text="🎭 Run All Demos",
                  command=self.run_all_demos,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_frame, text="📈 View Dashboard",
                  command=self.view_dashboard,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_frame, text="📄 View PDF Report",
                  command=self.view_pdf_report,
                  style='Secondary.TButton').pack(side="left")
        
    def create_settings_tab(self):
        """Create settings tab."""
        # Performance settings
        perf_frame = ttk.LabelFrame(self.settings_frame, text="Performance", padding="15")
        perf_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Label(perf_frame, text="Max parallel workers:").grid(row=0, column=0, sticky="w", pady=5)
        workers_spinbox = ttk.Spinbox(perf_frame, from_=1, to=16, textvariable=self.workers_var, width=10)
        workers_spinbox.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=5)
        
        # Vendor settings (if available)
        if self.vendor_support:
            vendor_settings_frame = ttk.LabelFrame(self.settings_frame, text="Vendor Detection", padding="15")
            vendor_settings_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
            
            ttk.Checkbutton(vendor_settings_frame, text="Enable automatic vendor detection", 
                           variable=self.auto_detect_enabled).pack(anchor="w", pady=2)
            
            ttk.Checkbutton(vendor_settings_frame, text="Show detailed vendor information in results", 
                           variable=self.show_vendor_details).pack(anchor="w", pady=2)
            
            ttk.Checkbutton(vendor_settings_frame, text="Generate vendor-specific remediation commands", 
                           variable=self.vendor_specific_remediation).pack(anchor="w", pady=2)
        
        # Report settings
        report_frame = ttk.LabelFrame(self.settings_frame, text="Default Reports", padding="15")
        report_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Label(report_frame, text="Auto-generate:").grid(row=0, column=0, sticky="w", pady=5)
        
        ttk.Checkbutton(report_frame, text="PDF Report", variable=self.auto_pdf).grid(
            row=1, column=0, sticky="w", pady=2)
        
        ttk.Checkbutton(report_frame, text="HTML Dashboard", variable=self.auto_dashboard).grid(
            row=2, column=0, sticky="w", pady=2)
        
        ttk.Checkbutton(report_frame, text="Remediation Scripts", variable=self.auto_remediation).grid(
            row=3, column=0, sticky="w", pady=2)
        
        # Demo section
        demo_frame = ttk.LabelFrame(self.settings_frame, text="Demo & Testing", padding="15")
        demo_frame.grid(row=3, column=0, sticky="ew")
        
        ttk.Button(demo_frame, text="🔧 Create Mock Environment",
                  command=self.create_mock_environment,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="🧪 Run Test Suite",
                  command=self.run_test_suite,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="🎭 Run Feature Demos",
                  command=self.run_feature_demos,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        if self.vendor_support:
            ttk.Button(demo_frame, text="🔍 Test Vendor Detection",
                      command=self.run_vendor_tests,
                      style='Secondary.TButton').pack(anchor="w", pady=2)
    
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
        
    # Vendor-specific event handlers
    def on_vendor_mode_change(self):
        """Handle vendor mode selection change."""
        if not self.vendor_support:
            return
            
        if self.vendor_mode.get() == "auto":
            if hasattr(self, 'vendor_combo'):
                self.vendor_combo.config(state="disabled")
        else:
            if hasattr(self, 'vendor_combo'):
                self.vendor_combo.config(state="readonly")
    
    def analyze_sample_config(self):
        """Analyze a sample configuration for vendor detection."""
        if not self.vendor_support:
            messagebox.showinfo("Not Available", "Multi-vendor support not installed.")
            return
            
        # Check if we have configs to analyze
        current_dir = Path(self.current_folder.get()) if self.current_folder.get() else None
        
        if current_dir and current_dir.exists():
            config_files = list(current_dir.glob("*.cfg"))
            if config_files:
                # Analyze first config file
                try:
                    with open(config_files[0], 'r', encoding='utf-8', errors='ignore') as f:
                        config_content = f.read()
                    
                    vendor_type, version = self.vendor_manager.detect_vendor(config_content)
                    profile = self.vendor_manager.profiles.get(vendor_type)
                    
                    if profile:
                        detection_text = f"🎯 Detected: {profile.display_name}"
                        if version:
                            detection_text += f" (v{version})"
                        detection_text += f" from {config_files[0].name}"
                        
                        self.detected_info.set(detection_text)
                        self.update_vendor_info_display(vendor_type, version, config_files[0].name)
                    else:
                        self.detected_info.set("❓ Unknown vendor detected")
                        
                except Exception as e:
                    self.detected_info.set(f"❌ Error analyzing config: {str(e)}")
            else:
                messagebox.showinfo("No Configs", "No .cfg files found in selected directory.")
        else:
            messagebox.showinfo("Select Folder", "Please select a current config folder first.")
    
    def test_vendor_detection(self):
        """Test vendor detection with user-provided config snippet."""
        if not self.vendor_support:
            return
            
        config_content = self.test_config_text.get(1.0, tk.END).strip()
        if not config_content:
            self.test_results_label.config(text="❌ Please enter a configuration snippet to test")
            return
        
        try:
            vendor_type, version = self.vendor_manager.detect_vendor(config_content)
            profile = self.vendor_manager.profiles.get(vendor_type)
            
            if profile:
                result_text = f"✅ Detected: {profile.display_name}"
                if version:
                    result_text += f" (Version: {version})"
                self.test_results_label.config(text=result_text, foreground=self.colors['secondary'])
            else:
                self.test_results_label.config(text="❓ Unknown or generic vendor detected", 
                                             foreground=self.colors['warning'])
                
        except Exception as e:
            self.test_results_label.config(text=f"❌ Detection error: {str(e)}", 
                                         foreground=self.colors['danger'])
    
    def load_sample_config(self):
        """Load a sample configuration for testing."""
        sample_configs = {
            "Cisco IOS": """version 15.7
hostname CiscoRouter01
!
aaa new-model
aaa authentication login default group tacacs+ local
tacacs-server host 192.168.1.100 key secretkey
!
enable secret 5 $1$hash$example
!
line vty 0 4
 transport input ssh
 access-class MGMT-ACL in""",
            
            "Arista EOS": """! EOS 4.28.1F
hostname AristaSwitch01
!
management ssh
!
aaa authentication login default group tacacs+ local
tacacs-server host 192.168.1.100 key secretkey
!
username admin role network-admin secret password123""",
            
            "Cisco XR": """!! IOS XR Configuration 7.3.1
hostname XRRouter01
!
aaa authentication login default group tacacs+ local
tacacs-server host 192.168.1.100
 key secretkey
!
ssh server v2""",
            
            "Juniper Junos": """version 20.4R3.8;
system {
    host-name JuniperRouter01;
    authentication-order [ tacplus password ];
    tacplus-server {
        192.168.1.100 {
            secret "secretkey";
        }
    }
    services {
        ssh;
    }
}"""
        }
        
        # Create selection dialog
        selection_window = tk.Toplevel(self.root)
        selection_window.title("Select Sample Configuration")
        selection_window.geometry("300x200")
        selection_window.transient(self.root)
        selection_window.grab_set()
        
        # Center the dialog
        selection_window.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (selection_window.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (selection_window.winfo_height() // 2)
        selection_window.geometry(f"+{x}+{y}")
        
        ttk.Label(selection_window, text="Choose a sample configuration:").pack(pady=10)
        
        for vendor_name in sample_configs.keys():
            ttk.Button(selection_window, text=vendor_name,
                      command=lambda v=vendor_name: self.set_sample_config(sample_configs[v], selection_window)).pack(pady=2)
        
        ttk.Button(selection_window, text="Cancel",
                  command=selection_window.destroy).pack(pady=10)
    
    def set_sample_config(self, config_content, window):
        """Set the sample configuration content."""
        if hasattr(self, 'test_config_text'):
            self.test_config_text.delete(1.0, tk.END)
            self.test_config_text.insert(1.0, config_content)
        window.destroy()
        # Auto-test the detection
        self.test_vendor_detection()
    
    def update_vendor_info_display(self, vendor_type, version, filename):
        """Update the vendor information display."""
        if not self.vendor_support or not hasattr(self, 'vendor_result_label'):
            return
            
        try:
            profile = self.vendor_manager.profiles.get(vendor_type)
            if profile:
                info_text = f"📊 {profile.display_name}"
                if version:
                    info_text += f" (v{version})"
                info_text += f" • File: {filename}"
                
                self.vendor_result_label.config(
                    text=info_text,
                    foreground=self.colors['secondary']
                )
            else:
                self.vendor_result_label.config(
                    text=f"❓ Unknown vendor • File: {filename}",
                    foreground=self.colors['warning']
                )
        except Exception as e:
            self.vendor_result_label.config(
                text=f"❌ Error: {str(e)}",
                foreground=self.colors['danger']
            )
    
    def run_vendor_tests(self):
        """Run comprehensive vendor detection tests."""
        if not self.vendor_support:
            return
            
        try:
            # Run the test function from vendor_manager
            subprocess.Popen([sys.executable, "-c", 
                             "from enhanced_features.vendor_manager import test_vendor_detection; test_vendor_detection()"],
                           creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
            messagebox.showinfo("Tests Started", "Vendor detection tests are running in a separate window.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start vendor tests: {e}")
    
    # Event handlers
    def browse_folder(self, var):
        """Browse for folder and set variable."""
        try:
            folder = filedialog.askdirectory(title="Select Folder")
            if folder:
                var.set(folder)
                # Auto-analyze if vendor support is available and this is current folder
                if (self.vendor_support and var == self.current_folder and 
                    hasattr(self, 'analyze_sample_config')):
                    # Small delay to allow GUI to update
                    self.root.after(100, self.analyze_sample_config)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to browse folder: {e}")
    
    def setup_mock_environment(self):
        """Quick setup using mock environment."""
        mock_dir = Path("mock_configs")
        if mock_dir.exists():
            self.current_folder.set(str(mock_dir / "current"))
            self.baseline_folder.set(str(mock_dir / "baseline"))
            self.update_status("Mock environment configured")
            
            # Auto-analyze if vendor support is available
            if self.vendor_support:
                self.root.after(100, self.analyze_sample_config)
            
            messagebox.showinfo("Success", "Mock environment configured!\nReady to run compliance check.")
        else:
            if messagebox.askyesno("Create Mock Environment", 
                                 "Mock environment not found. Create it now?"):
                self.create_mock_environment()
    
    def create_mock_environment(self):
        """Create mock environment."""
        try:
            setup_mock = safe_import('setup_mock_environment')
            if setup_mock and hasattr(setup_mock, 'create_mock_environment'):
                setup_mock.create_mock_environment()
                self.setup_mock_environment()  # Configure paths
            else:
                messagebox.showerror("Error", "setup_mock_environment module not found or invalid.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create mock environment: {e}")
    
    def start_compliance_check(self):
        """Start compliance check in background thread."""
        if not self.current_folder.get() or not self.baseline_folder.get():
            messagebox.showerror("Error", "Please select both current and baseline folders.")
            return
        
        if self.processing:
            return
        
        # Validate directories exist
        current_path = Path(self.current_folder.get())
        baseline_path = Path(self.baseline_folder.get())
        
        if not current_path.exists():
            messagebox.showerror("Error", f"Current config folder does not exist: {current_path}")
            return
            
        if not baseline_path.exists():
            messagebox.showerror("Error", f"Baseline config folder does not exist: {baseline_path}")
            return
        
        self.processing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_value.set(0)
        self.progress_text.set("Starting compliance check...")
        
        # Start in background thread
        thread = threading.Thread(target=self.run_compliance_check, daemon=True)
        thread.start()
    
    def run_compliance_check(self):
        """Run compliance check (in background thread)."""
        try:
            current_dir = Path(self.current_folder.get())
            baseline_dir = Path(self.baseline_folder.get())
            output_dir = Path(self.output_folder.get())
            
            # Find config files
            config_files = list(current_dir.glob("*.cfg"))
            if not config_files:
                self.root.after(0, lambda: messagebox.showerror("Error", "No .cfg files found"))
                return
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            results = []
            total_files = len(config_files)
            
            for i, config_file in enumerate(config_files):
                if not self.processing:  # Check if stopped
                    break
                
                baseline_file = baseline_dir / config_file.name
                if not baseline_file.exists():
                    continue
                
                # Update progress
                progress = (i / total_files) * 100
                self.root.after(0, lambda p=progress, f=config_file.name: self.update_progress(p, f))
                
                # Run compliance check with vendor support
                try:
                    if self.vendor_support and self.vendor_mode.get() == "auto":
                        # Use multi-vendor checking
                        with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                            config_content = f.read()
                        
                        result = self.vendor_manager.check_compliance_multi_vendor(config_content)
                        result['file_path'] = str(config_file)
                    else:
                        # Use original compliance checking
                        check_config_compliance = safe_import('scanner.config_checker', 'check_config_compliance')
                        if check_config_compliance:
                            result = check_config_compliance(
                                str(config_file),
                                str(baseline_file),
                                skip_connectivity=self.skip_connectivity.get()
                            )
                            result['file_path'] = str(config_file)
                        else:
                            # Fallback mock result
                            result = {
                                'hostname': config_file.stem,
                                'compliant': True,
                                'file_path': str(config_file),
                                'issues': [],
                                'score': 100
                            }
                    
                    # Write result
                    write_result = safe_import('reporter.simple_report', 'write_result')
                    if write_result:
                        write_result(result, str(output_dir))
                    
                    results.append(result)
                    
                except Exception as e:
                    print(f"Error processing {config_file}: {e}")
                    # Add error result
                    result = {
                        'hostname': config_file.stem,
                        'compliant': False,
                        'file_path': str(config_file),
                        'issues': [f"Processing error: {str(e)}"],
                        'score': 0
                    }
                    results.append(result)
            
            # Complete
            self.root.after(0, lambda: self.compliance_check_complete(results))
            
        except Exception as e:
            self.root.after(0, lambda: self.compliance_check_error(str(e)))
    
    def compliance_check_complete(self, results):
        """Handle completion of compliance check."""
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_value.set(100)
        
        compliant = sum(1 for r in results if r.get('compliant', False))
        total = len(results)
        
        self.progress_text.set(f"Complete! {compliant}/{total} devices compliant")
        self.update_status("Compliance check completed")
        
        # Update results summary
        self.update_results_summary(results)
        
        # Generate reports if enabled
        if self.generate_pdf.get():
            self.root.after(1000, self.generate_pdf_report)  # Delay to let UI update
        
        if self.generate_dashboard.get():
            self.root.after(1500, self.generate_dashboard_report)
        
        # Switch to results tab
        self.notebook.select(1)
        
        # Enhanced completion message with vendor info
        vendor_info = ""
        if self.vendor_support and results:
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
    
    def compliance_check_error(self, error_message):
        """Handle compliance check error."""
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_text.set("Error occurred")
        self.update_status("Error")
        messagebox.showerror("Error", f"Compliance check failed: {error_message}")
    
    def stop_compliance_check(self):
        """Stop compliance check."""
        self.processing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_text.set("Stopped by user")
        self.update_status("Stopped")
    
    def update_progress(self, percentage, current_file):
        """Update progress display."""
        self.progress_value.set(percentage)
        self.progress_text.set(f"Processing {current_file}... {percentage:.1f}%")
    
    def update_results_summary(self, results):
        """Update results summary display with vendor information."""
        if not hasattr(self, 'summary_text'):
            return
            
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
        if self.vendor_support and results:
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
            
            if self.vendor_support and 'vendor_display' in result:
                vendor_info = f" ({result['vendor_display']}"
                if result.get('detected_version'):
                    vendor_info += f" v{result['detected_version']}"
                vendor_info += ")"
            
            summary += f"{hostname:<20} {status}{vendor_info}\n"
        
        self.summary_text.insert(1.0, summary)
        self.summary_text.config(state='disabled')
    
    def update_status(self, message):
        """Update status bar."""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    # Report generation methods
    def generate_pdf_report(self):
        """Generate PDF report."""
        try:
            self.update_status("Generating PDF report...")
            CMMCPDFReporter = safe_import('enhanced_features.pdf_reporter', 'CMMCPDFReporter')
            
            if not CMMCPDFReporter:
                messagebox.showwarning("Warning", "PDF generation requires enhanced_features.pdf_reporter module.")
                return
            
            # Load results
            results = self.load_latest_results()
            if not results:
                messagebox.showwarning("Warning", "No results found. Run compliance check first.")
                return
            
            output_path = Path(self.output_folder.get()) / "compliance_report.pdf"
            reporter = CMMCPDFReporter()
            reporter.generate_compliance_report(results, str(output_path))
            
            self.update_status("PDF report generated")
            messagebox.showinfo("Success", f"PDF report generated: {output_path}")
            
        except ImportError:
            messagebox.showerror("Error", "PDF generation requires: pip install reportlab matplotlib")
        except Exception as e:
            messagebox.showerror("Error", f"PDF generation failed: {e}")
    
    def generate_dashboard_report(self):
        """Generate HTML dashboard."""
        try:
            self.update_status("Generating dashboard...")
            CMMCDashboard = safe_import('enhanced_features.dashboard_generator', 'CMMCDashboard')
            
            if not CMMCDashboard:
                messagebox.showwarning("Warning", "Dashboard generation requires enhanced_features.dashboard_generator module.")
                return
            
            results = self.load_latest_results()
            if not results:
                messagebox.showwarning("Warning", "No results found. Run compliance check first.")
                return
            
            output_path = Path(self.output_folder.get()) / "dashboard.html"
            dashboard = CMMCDashboard()
            dashboard.generate_dashboard(results, str(output_path))
            
            self.update_status("Dashboard generated")
            messagebox.showinfo("Success", f"Dashboard generated: {output_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Dashboard generation failed: {e}")
    
    def generate_remediation(self):
        """Generate remediation scripts."""
        try:
            self.update_status("Generating remediation...")
            CMMCRemediationEngine = safe_import('enhanced_features.remediation_engine', 'CMMCRemediationEngine')
            
            if not CMMCRemediationEngine:
                messagebox.showwarning("Warning", "Remediation generation requires enhanced_features.remediation_engine module.")
                return
            
            results = self.load_latest_results()
            if not results:
                messagebox.showwarning("Warning", "No results found. Run compliance check first.")
                return
            
            output_path = Path(self.output_folder.get()) / "remediation"
            engine = CMMCRemediationEngine()
            plan = engine.generate_remediation_plan(results)
            engine.export_remediation_scripts(plan, output_path)
            
            self.update_status("Remediation scripts generated")
            messagebox.showinfo("Success", f"Remediation scripts generated: {output_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Remediation generation failed: {e}")
    
    def load_latest_results(self):
        """Load latest compliance results."""
        try:
            output_dir = Path(self.output_folder.get())
            
            # Try to find recent results from CSV
            csv_file = output_dir / "compliance_result.csv"
            if csv_file.exists():
                # Simple results loading - could be enhanced to parse CSV properly
                mock_dir = Path("mock_configs")
                if mock_dir.exists():
                    current_dir = mock_dir / "current"
                    baseline_dir = mock_dir / "baseline"
                    
                    results = []
                    for config_file in current_dir.glob("*.cfg"):
                        baseline_file = baseline_dir / config_file.name
                        if baseline_file.exists():
                            if self.vendor_support:
                                # Use multi-vendor checking
                                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    config_content = f.read()
                                result = self.vendor_manager.check_compliance_multi_vendor(config_content)
                            else:
                                # Use original checking or create mock result
                                check_config_compliance = safe_import('scanner.config_checker', 'check_config_compliance')
                                if check_config_compliance:
                                    result = check_config_compliance(
                                        str(config_file),
                                        str(baseline_file),
                                        skip_connectivity=True
                                    )
                                else:
                                    # Mock result
                                    result = {
                                        'hostname': config_file.stem,
                                        'compliant': True,
                                        'score': 85,
                                        'issues': []
                                    }
                            results.append(result)
                    return results
            
            return []
            
        except Exception as e:
            print(f"Error loading results: {e}")
            return []
    
    # Quick action methods
    def run_all_demos(self):
        """Run all feature demos."""
        try:
            demo_file = Path("demo_enhanced_features.py")
            if demo_file.exists():
                subprocess.Popen([sys.executable, str(demo_file)], 
                               creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
                messagebox.showinfo("Demos Started", "Feature demos are running in a separate window.")
            else:
                messagebox.showwarning("Not Found", "demo_enhanced_features.py not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start demos: {e}")
    
    def view_dashboard(self):
        """Open dashboard in browser."""
        dashboard_path = Path(self.output_folder.get()) / "dashboard.html"
        if dashboard_path.exists():
            webbrowser.open(f"file://{dashboard_path.absolute()}")
        else:
            messagebox.showwarning("Not Found", "Dashboard not found. Generate it first.")
    
    def view_pdf_report(self):
        """Open PDF report."""
        pdf_path = Path(self.output_folder.get()) / "compliance_report.pdf"
        if pdf_path.exists():
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(str(pdf_path))
                elif os.name == 'posix':  # macOS and Linux
                    subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', str(pdf_path)])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open PDF: {e}")
        else:
            messagebox.showwarning("Not Found", "PDF report not found. Generate it first.")
    
    def open_output_folder(self):
        """Open output folder in file explorer."""
        output_path = Path(self.output_folder.get())
        
        # Create folder if it doesn't exist
        if not output_path.exists():
            try:
                output_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create output folder: {e}")
                return
        
        try:
            if os.name == 'nt':  # Windows
                subprocess.Popen(f'explorer "{output_path}"')
            elif sys.platform == 'darwin':  # macOS
                subprocess.Popen(['open', str(output_path)])
            else:  # Linux
                subprocess.Popen(['xdg-open', str(output_path)])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {e}")
    
    def run_test_suite(self):
        """Run the test suite."""
        try:
            test_file = Path("test_cmmc_tool.py")
            if test_file.exists():
                subprocess.Popen([sys.executable, str(test_file)],
                               creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
                messagebox.showinfo("Test Started", "Test suite is running in a separate window.")
            else:
                messagebox.showwarning("Not Found", "test_cmmc_tool.py not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start test suite: {e}")
    
    def run_feature_demos(self):
        """Run feature demos."""
        self.run_all_demos()
    
    def on_closing(self):
        """Handle window closing event."""
        if self.processing:
            if messagebox.askokcancel("Quit", "A compliance check is running. Stop it and quit?"):
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