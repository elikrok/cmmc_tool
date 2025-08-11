# enhanced_features/gui_enhancements.py
"""Enhanced GUI with progress tracking and advanced features."""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
from pathlib import Path

class EnhancedCMMCGUI:
    def __init__(self, root):
        self.root = root
        self.setup_gui()
        self.batch_processor = None
        
    def setup_gui(self):
        """Setup enhanced GUI with progress tracking."""
        self.root.title("CMMC 2.0 Compliance Tool - Enhanced")
        self.root.geometry("800x600")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main compliance check tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Compliance Check")
        
        # Results tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Results")
        
        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        self.setup_main_tab()
        self.setup_results_tab()
        self.setup_settings_tab()
    
    def setup_main_tab(self):
        """Setup main compliance check tab."""
        # File selection section
        file_frame = ttk.LabelFrame(self.main_frame, text="Configuration Files", padding=10)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Current configs
        ttk.Label(file_frame, text="Current Config Folder:").grid(row=0, column=0, sticky="w", pady=5)
        self.current_var = tk.StringVar()
        current_entry = ttk.Entry(file_frame, textvariable=self.current_var, width=60)
        current_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.current_var)).grid(row=0, column=2, padx=5)
        
        # Baseline configs
        ttk.Label(file_frame, text="Baseline Config Folder:").grid(row=1, column=0, sticky="w", pady=5)
        self.baseline_var = tk.StringVar()
        baseline_entry = ttk.Entry(file_frame, textvariable=self.baseline_var, width=60)
        baseline_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.baseline_var)).grid(row=1, column=2, padx=5)
        
        # Output directory
        ttk.Label(file_frame, text="Output Folder:").grid(row=2, column=0, sticky="w", pady=5)
        self.output_var = tk.StringVar(value="output")
        output_entry = ttk.Entry(file_frame, textvariable=self.output_var, width=60)
        output_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", 
                  command=lambda: self.browse_folder(self.output_var)).grid(row=2, column=2, padx=5)
        
        # Options section
        options_frame = ttk.LabelFrame(self.main_frame, text="Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.skip_connectivity_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Skip TACACS connectivity test", 
                       variable=self.skip_connectivity_var).pack(anchor="w")
        
        self.parallel_processing_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable parallel processing", 
                       variable=self.parallel_processing_var).pack(anchor="w")
        
        self.generate_pdf_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Generate PDF report", 
                       variable=self.generate_pdf_var).pack(anchor="w")
        
        self.generate_dashboard_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Generate HTML dashboard", 
                       variable=self.generate_dashboard_var).pack(anchor="w")
        
        # Progress section
        progress_frame = ttk.LabelFrame(self.main_frame, text="Progress", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.StringVar(value="Ready to start...")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(anchor="w")
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Compliance Check", 
                                      command=self.start_compliance_check)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", 
                                     command=self.stop_compliance_check, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Open Output Folder", 
                  command=self.open_output_folder).pack(side=tk.RIGHT, padx=5)
    
    def setup_results_tab(self):
        """Setup results display tab."""
        # Results tree
        tree_frame = ttk.Frame(self.results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create Treeview
        columns = ('Device', 'Status', 'Controls Passed', 'Issues')
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details section
        details_frame = ttk.LabelFrame(self.results_frame, text="Device Details", padding=10)
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
        details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scrollbar.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.results_tree.bind('<<TreeviewSelect>>', self.on_device_select)
    
    def setup_settings_tab(self):
        """Setup settings tab."""
        settings_main = ttk.Frame(self.settings_frame)
        settings_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Performance settings
        perf_frame = ttk.LabelFrame(settings_main, text="Performance", padding=10)
        perf_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(perf_frame, text="Max parallel workers:").grid(row=0, column=0, sticky="w")
        self.workers_var = tk.IntVar(value=4)
        workers_spinbox = ttk.Spinbox(perf_frame, from_=1, to=16, textvariable=self.workers_var, width=10)
        workers_spinbox.grid(row=0, column=1, padx=5)
        
        # Report settings
        report_frame = ttk.LabelFrame(settings_main, text="Reporting", padding=10)
        report_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(report_frame, text="Default output format:").grid(row=0, column=0, sticky="w")
        self.format_var = tk.StringVar(value="All formats")
        format_combo = ttk.Combobox(report_frame, textvariable=self.format_var, 
                                   values=["Text only", "CSV only", "JSON only", "All formats"])
        format_combo.grid(row=0, column=1, padx=5, sticky="w")
        
        # Advanced settings
        advanced_frame = ttk.LabelFrame(settings_main, text="Advanced", padding=10)
        advanced_frame.pack(fill=tk.X, pady=5)
        
        self.debug_mode_var = tk.BooleanVar()
        ttk.Checkbutton(advanced_frame, text="Enable debug logging", 
                       variable=self.debug_mode_var).pack(anchor="w")
        
        self.auto_remediation_var = tk.BooleanVar()
        ttk.Checkbutton(advanced_frame, text="Generate remediation commands", 
                       variable=self.auto_remediation_var).pack(anchor="w")
    
    def browse_folder(self, var):
        """Browse for folder and set variable."""
        folder = filedialog.askdirectory()
        if folder:
            var.set(folder)
    
    def start_compliance_check(self):
        """Start compliance check in background thread."""
        # Validate inputs
        if not self.current_var.get() or not self.baseline_var.get():
            messagebox.showerror("Error", "Please select both current and baseline config folders.")
            return
        
        # Disable start button, enable stop button
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.details_text.delete(1.0, tk.END)
        
        # Start processing in background thread
        self.processing_thread = threading.Thread(target=self.run_compliance_check)
        self.processing_thread.daemon = True
        self.processing_thread.start()
    
    def run_compliance_check(self):
        """Run compliance check (called in background thread)."""
        try:
            from enhanced_features.batch_processor import CMMCBatchProcessor
            
            # Initialize batch processor
            max_workers = self.workers_var.get() if self.parallel_processing_var.get() else 1
            self.batch_processor = CMMCBatchProcessor(max_workers=max_workers)
            
            # Process directories
            results = self.batch_processor.process_directory(
                current_dir=self.current_var.get(),
                baseline_dir=self.baseline_var.get(),
                output_dir=self.output_var.get(),
                skip_connectivity=self.skip_connectivity_var.get(),
                progress_callback=self.update_progress
            )
            
            # Update UI in main thread
            self.root.after(0, self.processing_complete, results)
            
        except Exception as e:
            self.root.after(0, self.processing_error, str(e))
    
    def update_progress(self, percentage, current_file):
        """Update progress (called from background thread)."""
        def update_ui():
            self.progress_bar['value'] = percentage
            self.progress_var.set(f"Processing {current_file}... {percentage:.1f}%")
        
        self.root.after(0, update_ui)
    
    def processing_complete(self, results):
        """Handle completion of processing."""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        self.progress_var.set(f"Complete! Processed {results['total_processed']} devices. "
                             f"{results['compliant_devices']} compliant.")
        self.progress_bar['value'] = 100
        
        # Populate results tree
        self.populate_results_tree(results['results'])
        
        # Switch to results tab
        self.notebook.select(1)
        
        # Generate additional reports if requested
        if self.generate_dashboard_var.get():
            self.generate_dashboard(results['results'])
        
        if self.generate_pdf_var.get():
            self.generate_pdf_report(results['results'])
        
        messagebox.showinfo("Complete", 
                           f"Compliance check complete!\n"
                           f"Processed: {results['total_processed']} devices\n"
                           f"Compliant: {results['compliant_devices']} devices\n"
                           f"Output saved to: {results['output_directory']}")
    
    def processing_error(self, error_message):
        """Handle processing error."""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set("Error occurred during processing")
        messagebox.showerror("Error", f"Processing failed: {error_message}")
    
    def stop_compliance_check(self):
        """Stop compliance check."""
        # In a real implementation, you'd need to signal the background thread to stop
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set("Stopped by user")
    
    def populate_results_tree(self, results):
        """Populate the results tree with compliance data."""
        for result in results:
            hostname = result.get('hostname', 'Unknown')
            compliant = result.get('compliant', False)
            status = "Compliant" if compliant else "Non-Compliant"
            
            checks = result.get('checks', {})
            controls_passed = sum(1 for check in checks.values() if check.get('passed', False))
            total_controls = len(checks)
            
            # Count issues
            issues = []
            for control, data in checks.items():
                if not data.get('passed', True):
                    issues.append(control)
            
            issue_count = len(issues)
            issue_text = f"{issue_count} issues" if issue_count > 0 else "No issues"
            
            # Insert into tree
            item = self.results_tree.insert('', 'end', values=(
                hostname, status, f"{controls_passed}/{total_controls}", issue_text
            ))
            
            # Store full result data
            self.results_tree.set(item, 'result_data', result)
    
    def on_device_select(self, event):
        """Handle device selection in results tree."""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        result_data = self.results_tree.set(item, 'result_data')
        
        if result_data:
            self.display_device_details(result_data)
    
    def display_device_details(self, result):
        """Display detailed information for selected device."""
        self.details_text.delete(1.0, tk.END)
        
        hostname = result.get('hostname', 'Unknown')
        compliant = result.get('compliant', False)
        
        details = f"Device: {hostname}\n"
        details += f"Overall Status: {'COMPLIANT' if compliant else 'NON-COMPLIANT'}\n\n"
        details += "Control Details:\n"
        details += "-" * 40 + "\n"
        
        checks = result.get('checks', {})
        for control, data in checks.items():
            status = "PASS" if data.get('passed', False) else "FAIL"
            details += f"{control}: {status}\n"
            
            # Add specific details based on control
            if control == 'AC.L1-3.1.1':
                details += f"  • AAA Configured: {'Yes' if data.get('aaa_configured') else 'No'}\n"
                details += f"  • TACACS Servers: {len(data.get('tacacs_servers', []))}\n"
            elif control == 'AC.L1-3.1.2':
                details += f"  • Enable Secret: {'Yes' if data.get('enable_secret_present') else 'No'}\n"
                details += f"  • No Telnet: {'Yes' if data.get('no_telnet') else 'No'}\n"
            elif control == 'SC.L1-3.13.1':
                details += f"  • SSH Management: {'Yes' if data.get('ssh_mgmt') else 'No'}\n"
                details += f"  • ACLs Applied: {'Yes' if data.get('acls_present_and_applied') else 'No'}\n"
            elif control == 'SC.L1-3.13.5':
                dmz_issues = len(data.get('dmz_interfaces_without_acl', []))
                details += f"  • DMZ Interfaces Missing ACL: {dmz_issues}\n"
            
            details += "\n"
        
        self.details_text.insert(1.0, details)
    
    def generate_dashboard(self, results):
        """Generate HTML dashboard."""
        try:
            from enhanced_features.dashboard_generator import CMMCDashboard
            dashboard = CMMCDashboard()
            output_path = Path(self.output_var.get()) / "dashboard.html"
            dashboard.generate_dashboard(results, str(output_path))
            self.progress_var.set(f"Dashboard generated: {output_path}")
        except Exception as e:
            print(f"Dashboard generation failed: {e}")
    
    def generate_pdf_report(self, results):
        """Generate PDF report."""
        try:
            from enhanced_features.pdf_reporter import CMMCPDFReporter
            pdf_reporter = CMMCPDFReporter()
            output_path = Path(self.output_var.get()) / "compliance_report.pdf"
            pdf_reporter.generate_compliance_report(results, str(output_path))
            self.progress_var.set(f"PDF report generated: {output_path}")
        except Exception as e:
            print(f"PDF generation failed: {e}")
    
    def open_output_folder(self):
        """Open output folder in file explorer."""
        output_path = Path(self.output_var.get())
        if output_path.exists():
            import subprocess
            import sys
            
            if sys.platform == "win32":
                subprocess.Popen(f'explorer "{output_path}"')
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(output_path)])
            else:
                subprocess.Popen(["xdg-open", str(output_path)])