# WiFi Security Analyzer

Production-oriented Python CLI for authorized wireless security assessment.

It scans nearby WiFi networks on Linux using `iw`, `iwlist`, or `nmcli`, analyses
encryption and configuration risks, detects rogue AP indicators, and produces
CLI, JSON, and PDF reports. Demo data is available only when explicitly enabled.

> Use this tool only on networks you own or have written permission to assess.

## Features

| Feature | Details |
| --- | --- |
| Multi-tool scanning | Tries `iw`, `iwlist`, then `nmcli` |
| Safe demo mode | Demo data requires `--demo`; live scan failures are not faked |
| Encryption analysis | OPEN, WEP, WPA, WPA2, WPA3, UNKNOWN |
| Configuration checks | Default SSID patterns, WPS, hidden SSID, signal leakage, channel hygiene |
| Rogue AP detection | Duplicate SSID, encryption mismatch, evil-twin indicators |
| Risk scoring | Weighted 0-100 composite score |
| Reports | Rich CLI, JSON, and optional ReportLab PDF |
| Hardening | Input validation, argv-only subprocesses, structured logs, atomic JSON writes |
| Tests/tooling | Pytest, Ruff, mypy, Bandit, pip-audit configuration |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Ubuntu/Debian/Kali, install scan tools as needed:

```bash
sudo apt update
sudo apt install -y iw wireless-tools network-manager
```

For development and validation:

```bash
pip install -r requirements-dev.txt
```

## Usage

Live scan:

```bash
sudo python main.py --scan --interface wlan0 --output cli
```

Demo scan with all reports:

```bash
python main.py --scan --demo --output all --verbose
```

JSON report:

```bash
python main.py --scan --interface wlan0 --output json
```

PDF report:

```bash
python main.py --scan --interface wlan0 --output pdf
```

History and comparison:

```bash
python main.py --history
python main.py --compare output/report_a.json output/report_b.json
```

## Validation

```bash
python -m compileall -q analyzer config reporting risk_engine scanner utils main.py
ruff format --check .
ruff check .
mypy .
bandit -c pyproject.toml -r .
pip-audit -r requirements.txt
pytest
```

## Architecture

```text
wifi-sec-analyzer/
  main.py                    CLI and analysis pipeline
  config/settings.py         Constants, weights, thresholds
  scanner/scan.py            Tool orchestration and subprocess boundaries
  scanner/parser.py          iw, iwlist, nmcli parsers
  analyzer/encryption.py     Encryption posture findings
  analyzer/vulnerabilities.py Configuration findings
  analyzer/rogue.py          Rogue AP indicators
  risk_engine/scoring.py     Weighted scoring
  reporting/report_cli.py    Rich terminal report
  reporting/report_json.py   Atomic JSON report
  reporting/report_pdf.py    Optional PDF report
  utils/helpers.py           Validation, logging, safe IO, command execution
  tests/                     Regression and security-focused tests
```

## Security Notes

- Subprocess execution uses `shell=False` and validated argv lists.
- Interface names and scan durations are validated before reaching OS tools.
- Dynamic terminal output is escaped to prevent Rich markup injection.
- JSON report loading is size-bounded and limited to `.json` files.
- Report and history writes are atomic to avoid partial files.
- Structured logs are written under `logs/` and excluded from version control.
- Generated reports are written under `output/` and excluded from version control.

## License

MIT License. See `LICENSE`.
