
import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from scanner.config_checker import check_config_compliance
from reporter.simple_report import write_result
from reporter.web_report import write_html_report, write_json_report

def browse_folder(entry):
    path = filedialog.askdirectory()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def run_check():
    cfg = cfg_entry.get().strip().strip('"')
    base = base_entry.get().strip().strip('"')
    skip = skip_var.get() == 1

    if not cfg or not base:
        messagebox.showerror('Missing info', 'Please select both CURRENT and BASELINE folders.')
        return
    cfg_path = Path(cfg)
    base_path = Path(base)
    files = list(cfg_path.glob('*.cfg'))
    if not files:
        messagebox.showerror('No files', f'No .cfg files found in {cfg_path}')
        return

    out_dir = Path(ROOT_DIR) / 'output'
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    aggregated = []
    for p in files:
        baseline = base_path / p.name
        if not baseline.exists():
            continue
        result = check_config_compliance(str(p), str(baseline), skip_connectivity=skip)
        result['file_path'] = str(p.resolve())
        write_result(result, str(out_dir))
        aggregated.append(result)
        count += 1

    write_html_report(aggregated, str(out_dir), open_in_browser=bool(open_html_var.get()))
    if bool(write_json_var.get()):
        write_json_report(aggregated, str(out_dir))
    messagebox.showinfo('Done', f"Compliance check complete for {count} file(s).\nSee the 'output' folder for HTML, TXT, and CSV reports.")

def main():
    root = tk.Tk()
    root.title('CMMC Tool – Folder Mode')

    tk.Label(root, text='Current Config Folder:').grid(row=0, column=0, sticky='e', padx=6, pady=6)
    global cfg_entry
    cfg_entry = tk.Entry(root, width=54)
    cfg_entry.grid(row=0, column=1, padx=6, pady=6)
    tk.Button(root, text='Browse', command=lambda: browse_folder(cfg_entry)).grid(row=0, column=2, padx=6, pady=6)

    tk.Label(root, text='Baseline Config Folder:').grid(row=1, column=0, sticky='e', padx=6, pady=6)
    global base_entry
    base_entry = tk.Entry(root, width=54)
    base_entry.grid(row=1, column=1, padx=6, pady=6)
    tk.Button(root, text='Browse', command=lambda: browse_folder(base_entry)).grid(row=1, column=2, padx=6, pady=6)

    global skip_var
    skip_var = tk.IntVar(value=1)
    tk.Checkbutton(root, text='Skip TACACS connectivity check', variable=skip_var).grid(row=2, column=0, columnspan=3, padx=6, pady=6, sticky='w')

    open_html_var = tk.IntVar(value=1)
    write_json_var = tk.IntVar(value=1)
    tk.Checkbutton(root, text='Open HTML report when done', variable=open_html_var).grid(row=3, column=0, columnspan=3, sticky='w', padx=6, pady=0)
    tk.Checkbutton(root, text='Also write JSON report', variable=write_json_var).grid(row=4, column=0, columnspan=3, sticky='w', padx=6, pady=0)

    tk.Button(root, text='Run Compliance Check', command=run_check).grid(row=3, column=0, columnspan=3, pady=12)

    root.mainloop()

if __name__ == '__main__':
    main()
