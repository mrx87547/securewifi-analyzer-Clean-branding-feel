# 📡 WiFi Security Analyzer

A production-quality, modular Python CLI tool for wireless network security assessment on Linux.  
Scans nearby networks, identifies vulnerabilities, maps risks, simulates unauthorized access scenarios (**educational text only — no attack code**), and generates rich CLI, JSON, and PDF reports.

> **For authorized security assessment only.  Do not use on networks you do not own or have explicit permission to test.**

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **Multi-tool scanning** | Tries `iw` → `iwlist` → `nmcli`; graceful fallback to demo dataset |
| **Encryption analysis** | OPEN / WEP / WPA / WPA2 / WPA3 with detailed findings |
| **Configuration checks** | Default SSIDs, WPS, hidden SSIDs, signal leakage, channel issues |
| **Rogue AP detection** | Duplicate SSID, encryption mismatch, evil-twin identification |
| **Risk scoring engine** | Weighted composite score (0–100) across 4 dimensions |
| **Unauthorized access simulation** | Educational, text-only explanations — zero exploit code |
| **Rich CLI output** | Colour-coded tables, per-network panels, high-priority alerts |
| **JSON reports** | Structured, machine-readable reports with full vulnerability detail |
| **PDF reports** | Professional multi-section PDF via ReportLab (optional) |
| **Scan history** | Persistent history with summary table |
| **Scan comparison** | Diff two JSON reports to track changes over time |

---

## 🗂 Project Structure

```
wifi-sec-analyzer/
├── main.py                    # CLI entry point & analysis pipeline
├── requirements.txt
├── config/
│   └── settings.py            # Global constants, weights, thresholds
├── scanner/
│   ├── scan.py                # Executes iw / iwlist / nmcli
│   └── parser.py              # Parses raw tool output → network dicts
├── analyzer/
│   ├── encryption.py          # Encryption type analysis + findings
│   ├── vulnerabilities.py     # Config-based vulnerability checks
│   └── rogue.py               # Rogue AP / evil-twin detection
├── risk_engine/
│   └── scoring.py             # Weighted composite risk scoring
├── reporting/
│   ├── report_cli.py          # Rich terminal output
│   ├── report_json.py         # JSON report serialisation
│   └── report_pdf.py          # PDF report (ReportLab)
├── utils/
│   └── helpers.py             # Shared utilities, logging, shell runner
└── output/                    # Generated reports land here
```

---

## 🔧 Installation

### Prerequisites

```bash
# Ubuntu / Debian / Kali
sudo apt update
sudo apt install -y iw wireless-tools network-manager python3 python3-pip
```

### Python Dependencies

```bash
git clone https://github.com/your-username/wifi-sec-analyzer.git
cd wifi-sec-analyzer
pip install rich                # Required — terminal output
pip install reportlab           # Optional — PDF generation
```

Or install all at once:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic scan (CLI output)

```bash
sudo python main.py --scan --interface wlan0 --output cli
```

### Verbose scan with all output formats

```bash
sudo python main.py --scan --interface wlan0 --output all --verbose
```

### JSON report only

```bash
sudo python main.py --scan --interface wlan0 --output json
```

### PDF report

```bash
sudo python main.py --scan --interface wlan0 --output pdf
```

### View scan history

```bash
python main.py --history
```

### Compare two scans

```bash
python main.py --compare output/wsa_report_20240101_120000.json output/wsa_report_20240108_120000.json
```

### Demo mode (no wireless adapter required)

```bash
python main.py --scan --output all --verbose
# If no scan tools work, a realistic demo dataset is used automatically.
```

---

## 📋 Command Reference

```
usage: wsa [-h] [--scan] [--interface IFACE] [--output {cli,json,pdf,all}]
           [--duration SECS] [--verbose] [--history]
           [--compare SCAN_A SCAN_B] [--debug]

Options:
  --scan              Perform a wireless network scan
  --interface IFACE   Wireless interface (default: wlan0)
  --output FORMAT     cli | json | pdf | all  (default: cli)
  --duration SECS     Scan timeout in seconds (default: 15)
  --verbose           Show detailed per-network vulnerability panels
  --history           Show previous scan history
  --compare A B       Diff two JSON reports
  --debug             Enable debug logging
```

---

## 🔍 Risk Score Breakdown

| Factor | Weight | Details |
|--------|--------|---------|
| Encryption | 40 % | WPA3=0, WPA2=25, WPA=50, WEP=90, OPEN=100 |
| Configuration | 30 % | Default SSID, WPS enabled, hidden SSID, channel issues |
| Signal leakage | 15 % | Very strong RSSI → wider attack surface |
| Rogue AP | 15 % | Duplicate SSID, encryption mismatch, evil-twin |

| Score | Label | Meaning |
|-------|-------|---------|
| 0–19 | **Secure** | Good security posture |
| 20–39 | **Moderate** | Minor issues, should be addressed |
| 40–64 | **Vulnerable** | Significant weaknesses present |
| 65–100 | **Critical** | Immediate action required |

---

## 📄 Sample JSON Output

```json
{
  "report_metadata": {
    "tool_name": "WiFi Security Analyzer",
    "tool_version": "1.0.0",
    "generated_at": "2024-01-15T14:32:00",
    "interface": "wlan0",
    "total_networks_found": 8
  },
  "statistics": {
    "total_networks": 8,
    "average_risk_score": 35.9,
    "by_encryption": { "OPEN": 2, "WEP": 1, "WPA2": 3, "WPA3": 1, "WPA": 1 },
    "by_risk_label": { "Critical": 0, "Vulnerable": 4, "Moderate": 2, "Secure": 2 },
    "open_networks": 2,
    "wep_networks": 1,
    "wps_enabled_count": 3
  },
  "networks": [
    {
      "ssid": "CoffeeShop_Free",
      "bssid": "AA:BB:CC:11:22:33",
      "encryption": "OPEN",
      "risk": {
        "score": 54,
        "label": "Vulnerable",
        "top_risk": "Open / Unencrypted Network"
      },
      "vulnerabilities": {
        "encryption": {
          "vulnerability": "Open / Unencrypted Network",
          "risk_level": "Critical",
          "unauthorized_access_scenario": "Any device within wireless range can associate...",
          "recommendation": "Enable WPA3 Personal encryption immediately..."
        }
      }
    }
  ]
}
```

---

## 🔐 Vulnerability Categories Detected

### Encryption Vulnerabilities
- **OPEN** — No authentication, all traffic in plain-text (Critical)
- **WEP** — Cryptographically broken, key recoverable in seconds (Critical)
- **WPA-TKIP** — Deprecated, practical forgery attacks exist (High)
- **WPA2-PSK** — Vulnerable to offline handshake attacks + WPS Pixie Dust (Moderate)
- **WPA3** — Current best-practice; flags outdated firmware (Low)

### Configuration Vulnerabilities
- **Default/Vendor SSID** — Indicates factory defaults still in use
- **WPS Enabled** — PIN reduces key-space to ~11,000 attempts
- **Hidden SSID** — Security through obscurity; trivially bypassed
- **Signal Leakage** — Strong signal widens attacker reach
- **Non-standard 2.4 GHz channel** — Increases interference / IV capture rate

### Rogue AP Detection
- **Duplicate SSID** — Multiple BSSIDs for same network name
- **Encryption mismatch** — Same SSID with inconsistent security
- **Evil-twin indicator** — Open AP cloning an encrypted network's name

---

## ⚙️ Architecture Notes

- **Modular**: each concern lives in its own module; easy to extend
- **Type-annotated**: all public functions include type hints
- **Documented**: all functions have docstrings
- **Safe fallback**: no tool → demo dataset; no ReportLab → skip PDF
- **No root required** for nmcli / demo mode; `iw` / `iwlist` scan requires root
- **Logging**: file-based daily log in `logs/`; configurable verbosity

---

## ⚠️ Ethical & Legal Disclaimer

This tool is intended **exclusively for authorized security assessments** of networks you own or have explicit written permission to test.

- Unauthorized interception of wireless communications is illegal in most jurisdictions (e.g. Computer Misuse Act 1990, CFAA, IT Act 2000)
- This tool contains **zero exploit, attack, or password-cracking code**
- All "unauthorized access scenarios" are **educational text descriptions only**
- The authors accept no liability for misuse

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

PRs welcome.  Please ensure:
- All new functions include type hints and docstrings
- No attack code of any kind
- Tests pass with `python -m pytest` (if test suite is added)
