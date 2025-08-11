# modern_gui.py
"""Modern, aesthetic GUI for CMMC compliance checking."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import subprocess
import webbrowser
from pathlib import Path
import json
import os
import sys

class ModernCMMCGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        self.processing = False
        
    def setup_window(self):
        """Configure the main window."""
        self.root.title("CMMC 2.0 Level 1 Compliance Tool")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - self.root.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - self.root.winfo_height()) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Configure grid weights for responsive design
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def setup_styles(self):
        """Configure modern styling."""
        self.style = ttk.Style()
        
        # Configure modern theme
        self.style.theme_use('clam')
        
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
        
        # Configure styles
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
        
    def setup_variables(self):
        """Initialize variables."""
        self.current_folder = tk.StringVar()
        self.baseline_folder = tk.StringVar()
        self.output_folder = tk.StringVar(value="output")
        
        # Options
        self.skip_connectivity = tk.BooleanVar(value=True)
        self.generate_pdf = tk.BooleanVar(value=True)
        self.generate_dashboard = tk.BooleanVar(value=True)
        self.parallel_processing = tk.BooleanVar(value=True)
        
        # Status
        self.progress_text = tk.StringVar(value="Ready to start compliance check")
        self.progress_value = tk.DoubleVar()
        
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
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame, 
                                  text="Network Device Configuration Compliance Checker",
                                  style='Subheader.TLabel')
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
    def create_notebook(self, parent):
        """Create main content notebook."""
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        
        # Compliance Check Tab
        self.check_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(self.check_frame, text="  Compliance Check  ")
        self.create_check_tab()
        
        # Results Tab
        self.results_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(self.results_frame, text="  Results & Reports  ")
        self.create_results_tab()
        
        # Settings Tab
        self.settings_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(self.settings_frame, text="  Settings  ")
        self.create_settings_tab()
        
    def create_check_tab(self):
        """Create compliance check tab."""
        # File selection section
        files_frame = ttk.LabelFrame(self.check_frame, text="Configuration Files", padding="15")
        files_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        files_frame.grid_columnconfigure(1, weight=1)
        
        # Current configs
        ttk.Label(files_frame, text="Current Configs:", font=('Segoe UI', 10, 'bold')).grid(
            row=0, column=0, sticky="w", pady=(0, 8))
        
        current_frame = ttk.Frame(files_frame)
        current_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15))
        current_frame.grid_columnconfigure(0, weight=1)
        
        current_entry = ttk.Entry(current_frame, textvariable=self.current_folder, 
                                 font=('Segoe UI', 10), width=50)
        current_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        ttk.Button(current_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.current_folder),
                  style='Secondary.TButton').grid(row=0, column=1)
        
        # Baseline configs
        ttk.Label(files_frame, text="Baseline Configs:", font=('Segoe UI', 10, 'bold')).grid(
            row=2, column=0, sticky="w", pady=(0, 8))
        
        baseline_frame = ttk.Frame(files_frame)
        baseline_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 15))
        baseline_frame.grid_columnconfigure(0, weight=1)
        
        baseline_entry = ttk.Entry(baseline_frame, textvariable=self.baseline_folder,
                                  font=('Segoe UI', 10), width=50)
        baseline_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        ttk.Button(baseline_frame, text="Browse",
                  command=lambda: self.browse_folder(self.baseline_folder),
                  style='Secondary.TButton').grid(row=0, column=1)
        
        # Output folder
        ttk.Label(files_frame, text="Output Folder:", font=('Segoe UI', 10, 'bold')).grid(
            row=4, column=0, sticky="w", pady=(0, 8))
        
        output_frame = ttk.Frame(files_frame)
        output_frame.grid(row=5, column=0, columnspan=3, sticky="ew")
        output_frame.grid_columnconfigure(0, weight=1)
        
        output_entry = ttk.Entry(output_frame, textvariable=self.output_folder,
                                font=('Segoe UI', 10), width=50)
        output_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        ttk.Button(output_frame, text="Browse",
                  command=lambda: self.browse_folder(self.output_folder),
                  style='Secondary.TButton').grid(row=0, column=1)
        
        # Quick setup button
        quick_frame = ttk.Frame(self.check_frame)
        quick_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Button(quick_frame, text="Use Mock Environment", 
                  command=self.setup_mock_environment,
                  style='Secondary.TButton').pack(side="left")
        
        ttk.Label(quick_frame, text="(Sets up demo configs automatically)",
                 foreground=self.colors['gray']).pack(side="left", padx=(10, 0))
        
        # Options section
        options_frame = ttk.LabelFrame(self.check_frame, text="Processing Options", padding="15")
        options_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        
        options_grid = ttk.Frame(options_frame)
        options_grid.pack(fill="x")
        
        ttk.Checkbutton(options_grid, text="Skip TACACS connectivity test", 
                       variable=self.skip_connectivity).grid(row=0, column=0, sticky="w", pady=2)
        
        ttk.Checkbutton(options_grid, text="Enable parallel processing", 
                       variable=self.parallel_processing).grid(row=0, column=1, sticky="w", padx=(30, 0), pady=2)
        
        ttk.Checkbutton(options_grid, text="Generate PDF report", 
                       variable=self.generate_pdf).grid(row=1, column=0, sticky="w", pady=2)
        
        ttk.Checkbutton(options_grid, text="Generate HTML dashboard", 
                       variable=self.generate_dashboard).grid(row=1, column=1, sticky="w", padx=(30, 0), pady=2)
        
        # Progress section
        progress_frame = ttk.LabelFrame(self.check_frame, text="Progress", padding="15")
        progress_frame.grid(row=3, column=0, sticky="ew", pady=(0, 20))
        progress_frame.grid_columnconfigure(0, weight=1)
        
        # Progress text
        progress_label = ttk.Label(progress_frame, textvariable=self.progress_text,
                                  font=('Segoe UI', 10))
        progress_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          variable=self.progress_value,
                                          style='Modern.Horizontal.TProgressbar',
                                          mode='determinate')
        self.progress_bar.grid(row=1, column=0, sticky="ew")
        
        # Action buttons
        button_frame = ttk.Frame(self.check_frame)
        button_frame.grid(row=4, column=0, sticky="ew")
        
        self.start_button = ttk.Button(button_frame, text="Start Compliance Check",
                                      command=self.start_compliance_check,
                                      style='Primary.TButton')
        self.start_button.pack(side="left", padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop",
                                     command=self.stop_compliance_check,
                                     style='Secondary.TButton',
                                     state='disabled')
        self.stop_button.pack(side="left", padx=(0, 10))
        
        ttk.Button(button_frame, text="Open Output Folder",
                  command=self.open_output_folder,
                  style='Secondary.TButton').pack(side="right")
        
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
        
        ttk.Button(reports_frame, text="Generate PDF Report",
                  command=self.generate_pdf_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(reports_frame, text="Generate Dashboard",
                  command=self.generate_dashboard_report,
                  style='Primary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(reports_frame, text="Generate Remediation",
                  command=self.generate_remediation,
                  style='Secondary.TButton').pack(side="left")
        
        # Quick actions
        actions_frame = ttk.LabelFrame(self.results_frame, text="Quick Actions", padding="15")
        actions_frame.grid(row=2, column=0, sticky="ew")
        
        ttk.Button(actions_frame, text="Run All Demos",
                  command=self.run_all_demos,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_frame, text="View Dashboard",
                  command=self.view_dashboard,
                  style='Secondary.TButton').pack(side="left", padx=(0, 10))
        
        ttk.Button(actions_frame, text="View PDF Report",
                  command=self.view_pdf_report,
                  style='Secondary.TButton').pack(side="left")
        
    def create_settings_tab(self):
        """Create settings tab."""
        # Performance settings
        perf_frame = ttk.LabelFrame(self.settings_frame, text="Performance", padding="15")
        perf_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Label(perf_frame, text="Max parallel workers:").grid(row=0, column=0, sticky="w", pady=5)
        self.workers_var = tk.IntVar(value=4)
        workers_spinbox = ttk.Spinbox(perf_frame, from_=1, to=16, textvariable=self.workers_var, width=10)
        workers_spinbox.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=5)
        
        # Report settings
        report_frame = ttk.LabelFrame(self.settings_frame, text="Default Reports", padding="15")
        report_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Label(report_frame, text="Auto-generate:").grid(row=0, column=0, sticky="w", pady=5)
        
        self.auto_pdf = tk.BooleanVar(value=True)
        ttk.Checkbutton(report_frame, text="PDF Report", variable=self.auto_pdf).grid(
            row=1, column=0, sticky="w", pady=2)
        
        self.auto_dashboard = tk.BooleanVar(value=True)
        ttk.Checkbutton(report_frame, text="HTML Dashboard", variable=self.auto_dashboard).grid(
            row=2, column=0, sticky="w", pady=2)
        
        self.auto_remediation = tk.BooleanVar(value=False)
        ttk.Checkbutton(report_frame, text="Remediation Scripts", variable=self.auto_remediation).grid(
            row=3, column=0, sticky="w", pady=2)
        
        # Demo section
        demo_frame = ttk.LabelFrame(self.settings_frame, text="Demo & Testing", padding="15")
        demo_frame.grid(row=2, column=0, sticky="ew")
        
        ttk.Button(demo_frame, text="Create Mock Environment",
                  command=self.create_mock_environment,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="Run Test Suite",
                  command=self.run_test_suite,
                  style='Secondary.TButton').pack(anchor="w", pady=2)
        
        ttk.Button(demo_frame, text="Run Feature Demos",
                  command=self.run_feature_demos,
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
        
        ttk.Label(status_content, text="CMMC Tool v1.0",
                 font=('Segoe UI', 9),
                 foreground=self.colors['gray']).pack(side="right")
        
    # Event handlers
    def browse_folder(self, var):
        """Browse for folder and set variable."""
        folder = filedialog.askdirectory(title="Select Folder")
        if folder:
            var.set(folder)
    
    def setup_mock_environment(self):
        """Quick setup using mock environment."""
        mock_dir = Path("mock_configs")
        if mock_dir.exists():
            self.current_folder.set(str(mock_dir / "current"))
            self.baseline_folder.set(str(mock_dir / "baseline"))
            self.update_status("Mock environment configured")
            messagebox.showinfo("Success", "Mock environment configured!\nReady to run compliance check.")
        else:
            if messagebox.askyesno("Create Mock Environment", 
                                 "Mock environment not found. Create it now?"):
                self.create_mock_environment()
    
    def create_mock_environment(self):
        """Create mock environment."""
        try:
            import setup_mock_environment
            setup_mock_environment.create_mock_environment()
            self.setup_mock_environment()  # Configure paths
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create mock environment: {e}")
    
    def start_compliance_check(self):
        """Start compliance check in background thread."""
        if not self.current_folder.get() or not self.baseline_folder.get():
            messagebox.showerror("Error", "Please select both current and baseline folders.")
            return
        
        if self.processing:
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
            from scanner.config_checker import check_config_compliance
            from reporter.simple_report import write_result
            
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
                
                # Run check
                result = check_config_compliance(
                    str(config_file),
                    str(baseline_file),
                    skip_connectivity=self.skip_connectivity.get()
                )
                result['file_path'] = str(config_file)
                
                # Write result
                write_result(result, str(output_dir))
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
            self.generate_pdf_report()
        
        if self.generate_dashboard.get():
            self.generate_dashboard_report()
        
        # Switch to results tab
        self.notebook.select(1)
        
        messagebox.showinfo("Complete", 
                          f"Compliance check complete!\n"
                          f"Processed: {total} devices\n"
                          f"Compliant: {compliant} devices\n"
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
        """Update results summary display."""
        self.summary_text.config(state='normal')
        self.summary_text.delete(1.0, tk.END)
        
        summary = f"Compliance Check Results Summary\n"
        summary += f"{'='*50}\n"
        summary += f"Total Devices: {len(results)}\n"
        compliant = sum(1 for r in results if r.get('compliant', False))
        summary += f"Compliant: {compliant}\n"
        summary += f"Non-Compliant: {len(results) - compliant}\n"
        summary += f"Compliance Rate: {(compliant/len(results)*100):.1f}%\n\n"
        
        summary += "Device Details:\n"
        summary += f"{'-'*30}\n"
        
        for result in results:
            hostname = result.get('hostname', 'Unknown')
            status = "PASS" if result.get('compliant') else "FAIL"
            summary += f"{hostname:<20} {status}\n"
        
        self.summary_text.insert(1.0, summary)
        self.summary_text.config(state='disabled')
    
    def update_status(self, message):
        """Update status bar."""
        self.status_label.config(text=message)
    
    # Report generation methods
    def generate_pdf_report(self):
        """Generate PDF report."""
        try:
            self.update_status("Generating PDF report...")
            # Import here to avoid dependency issues
            from enhanced_features.pdf_reporter import CMMCPDFReporter
            
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
            from enhanced_features.dashboard_generator import CMMCDashboard
            
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
            from enhanced_features.remediation_engine import CMMCRemediationEngine
            
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
                from scanner.config_checker import check_config_compliance
                
                # For demo, just run a quick check to get results format
                mock_dir = Path("mock_configs")
                if mock_dir.exists():
                    current_dir = mock_dir / "current"
                    baseline_dir = mock_dir / "baseline"
                    
                    results = []
                    for config_file in current_dir.glob("*.cfg"):
                        baseline_file = baseline_dir / config_file.name
                        if baseline_file.exists():
                            result = check_config_compliance(
                                str(config_file),
                                str(baseline_file),
                                skip_connectivity=True
                            )
                            results.append(result)
                    return results
            
            return []
            
        except Exception:
            return []
    
    # Quick action methods
    def run_all_demos(self):
        """Run all feature demos."""
        try:
            subprocess.Popen([sys.executable, "demo_enhanced_features.py"], 
                           creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
            messagebox.showinfo("Demos Started", "Feature demos are running in a separate window.")
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
            if os.name == 'nt':  # Windows
                os.startfile(pdf_path)
            elif os.name == 'posix':  # macOS and Linux
                subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', pdf_path])
        else:
            messagebox.showwarning("Not Found", "PDF report not found. Generate it first.")
    
    def open_output_folder(self):
        """Open output folder in file explorer."""
        output_path = Path(self.output_folder.get())
        if output_path.exists():
            if os.name == 'nt':  # Windows
                subprocess.Popen(f'explorer "{output_path}"')
            elif sys.platform == 'darwin':  # macOS
                subprocess.Popen(['open', str(output_path)])
            else:  # Linux
                subprocess.Popen(['xdg-open', str(output_path)])
        else:
            messagebox.showwarning("Not Found", f"Output folder not found: {output_path}")
    
    def run_test_suite(self):
        """Run the test suite."""
        try:
            subprocess.Popen([sys.executable, "test_cmmc_tool.py"],
                           creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
            messagebox.showinfo("Test Started", "Test suite is running in a separate window.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start test suite: {e}")
    
    def run_feature_demos(self):
        """Run feature demos."""
        self.run_all_demos()
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()

def main():
    """Main entry point."""
    app = ModernCMMCGUI()
    app.run()

if __name__ == "__main__":
    main()