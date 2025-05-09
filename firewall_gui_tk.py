#!/usr/bin/env python3
# firewall_gui_tk.py  –  Tkinter front-end for FirewallParser

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import datetime as _dt
import importlib.util as _iu

from FirewallParser import FirewallAnalyzer

# ---------- optional PDF support ------------------------------------ #
PDF_OK = _iu.find_spec("reportlab") is not None
if PDF_OK:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

# ---------- GUI callbacks ------------------------------------------- #
def pick_file() -> None:
    path = filedialog.askopenfilename(
        title="Choose firewall log CSV",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if path:
        csv_var.set(path)

def analyze() -> None:
    file_path = Path(csv_var.get())
    if not file_path.is_file():
        messagebox.showerror("Error", "Please select a valid CSV file.")
        return

    global last_report
    fa = FirewallAnalyzer(
        ip_thresh=ip_scale.get(),
        port_thresh=port_scale.get(),
        top_n=int(top_spin.get())
    )
    try:
        fa.consume_csv(file_path)
    except Exception as e:
        messagebox.showerror("Parse error", str(e))
        return

    # Build report text
    lines = [f"Analysis run: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}",
             f"Log file: {file_path}",
             ""]

    for cat, series in fa.top_table().items():
        lines.append(f"Top {fa.top_n} {cat}:")
        lines.append(series.to_string())
        lines.append("")

    lines.append("Firewall rule suggestion(s):")
    lines.extend(fa.rule_suggestions())
    last_report = "\n".join(lines)

    # Display
    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, last_report)
    output_box.config(state="disabled")

    export_btn.config(state="normal")   # enable export now that we have data

def export_report() -> None:
    if not last_report:
        return
    ftypes = [("Text file", "*.txt")]
    if PDF_OK:
        ftypes.append(("PDF", "*.pdf"))
    file_path = filedialog.asksaveasfilename(
        title="Save analysis",
        defaultextension=".txt",
        filetypes=ftypes)
    if not file_path:
        return

    if file_path.lower().endswith(".pdf") and PDF_OK:
        _save_pdf(file_path, last_report)
    else:
        Path(file_path).write_text(last_report, encoding="utf-8")
    messagebox.showinfo("Saved", f"Report written to\n{file_path}")

def _save_pdf(dest: str, text: str) -> None:
    c = canvas.Canvas(dest, pagesize=letter)
    w, h = letter
    margin, line_h = 40, 12
    y = h - margin
    for line in text.splitlines():
        if y < margin:
            c.showPage(); y = h - margin
        c.drawString(margin, y, line)
        y -= line_h
    c.save()

# ---------- UI ------------------------------------------------------- #
root = tk.Tk()
root.title("Firewall Log Analyzer")

main = ttk.Frame(root, padding=10)
main.grid(sticky="nsew")
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# File chooser
csv_var = tk.StringVar()
ttk.Label(main, text="Firewall CSV:").grid(row=0, column=0, sticky="w")
ttk.Entry(main, textvariable=csv_var, width=60).grid(row=0, column=1, sticky="ew")
ttk.Button(main, text="Browse…", command=pick_file).grid(row=0, column=2, padx=5)
main.columnconfigure(1, weight=1)

# Parameters
param = ttk.LabelFrame(main, text="Parameters", padding=10)
param.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")

ttk.Label(param, text="Top N:").grid(row=0, column=0, sticky="w")
top_spin = ttk.Spinbox(param, from_=1, to=50, width=5)
top_spin.set(10)
top_spin.grid(row=0, column=1, sticky="w", padx=(0, 15))

ttk.Label(param, text="IP coverage threshold").grid(row=0, column=2, sticky="w")
ip_scale = ttk.Scale(param, from_=0.5, to=1.0, value=0.9)
ip_scale.grid(row=0, column=3, sticky="ew", padx=(0, 15))

ttk.Label(param, text="Port coverage threshold").grid(row=0, column=4, sticky="w")
port_scale = ttk.Scale(param, from_=0.5, to=1.0, value=0.9)
port_scale.grid(row=0, column=5, sticky="ew")
param.columnconfigure(3, weight=1)
param.columnconfigure(5, weight=1)

# Action buttons
ttk.Button(main, text="Analyze", command=analyze).grid(row=2, column=2, sticky="e")
export_btn = ttk.Button(main, text="Export…", command=export_report, state="disabled")
export_btn.grid(row=2, column=1, sticky="e", padx=5)

# Output box
output_box = tk.Text(main, width=100, height=30, wrap="word", font=("Consolas", 10))
output_box.grid(row=3, column=0, columnspan=3, pady=(10, 0), sticky="nsew")
output_box.config(state="disabled")
main.rowconfigure(3, weight=1)

last_report = ""   # populated after first analysis
root.mainloop()
