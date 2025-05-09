# Firewall Log Analyzer

A scalable Python tool that parses large CSV firewall logs, highlights dominant traffic patterns, and auto‑suggests concise firewall rules.  Includes a Tkinter GUI with one‑click **TXT/PDF export** and can be packaged as a standalone executable.

---

## Features

| Capability                | Details                                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Chunk‑stream parsing**  | Handles multi‑GB CSVs without exhausting RAM.                                                                           |
| **Condensed rule engine** | Collapses source/destination IPs into minimal supernets (≤ /21 src, ≤ /20 dst) and groups dominant ports (≥ 1 % share). |
| **GUI**                   | Browse→Analyze→Export; results shown in a read‑only text widget.                                                        |
| **Export**                | Save the on‑screen report to **.txt** or **PDF** (uses *reportlab*).                                                    |
| **One‑file executable**   | Build with *PyInstaller* (`--onefile --windowed`).                                                                      |
| **Rare‑event hints**      | Lists destination ports that appear fewer than five times.                                                              |

---

## Requirements

* Python **3.8 +**
* Packages

  * `pandas`
  * `reportlab` *(optional – only for PDF export)*
  * `pyinstaller` *(only if you want to build the executable)*

```bash
pip install pandas reportlab pyinstaller
```

> Skip `reportlab` if you don’t need PDF; the GUI will hide that option.

---

## Repository layout

```
repo/
├─ FirewallParser.py      # core analysis engine (CLI‑ready)
├─ firewall_gui_tk.py     # Tkinter GUI front‑end
├─ README.md              # this file
└─ sample_logs.csv        # (optional) small demo dataset
```

---

## Quick start

### 1  Clone and install deps

```bash
git clone https://github.com/yourname/firewall‑analyzer.git
cd firewall‑analyzer
pip install -r requirements.txt   # optional convenience file
```

### 2  Run the GUI

```bash
python firewall_gui_tk.py
```

* Click **Browse…** and select your firewall CSV.
* Adjust *Top N* and coverage sliders if desired.
* Hit **Analyze** – results populate the text box.
* Click **Export…** to save `.txt` or `.pdf`.

### 3  CLI usage (headless servers)

```bash
python FirewallParser.py /path/to/firewall.csv --top 15 \
       --ip_threshold 0.95 --port_threshold 0.9
```

---

## CSV expectations

The parser understands either of these formats:

```csv
# key=value style
srcip="192.168.1.10",dstip="8.8.8.8",srcport="52345",dstport="53"...

# columnar CSV
srcip,dstip,srcport,dstport
192.168.1.10,8.8.8.8,52345,53
```

Other columns are ignored.

---

## Building a standalone executable (Windows/macOS/Linux)

```bash
pyinstaller --onefile --windowed firewall_gui_tk.py
```

* The binary appears in `dist/`.
* Ship only that file – no Python install required for users.
* If you included *reportlab*, the binary will embed it.

---

## Contributing

Pull requests welcome!  Please open an issue first to discuss major changes.

### Dev tips

* Keep GUI changes inside `firewall_gui_tk.py`; core logic lives in `FirewallParser.py`.
* Add unit tests under `tests/` – use small synthetic CSVs.
* Run `black` and `ruff` before pushing.

---

## License

[MIT](LICENSE) – free for personal and commercial use.

---

## Acknowledgements

Inspired by countless late‑night firewall audits 🙃
