"""
config/settings.py
Global configuration and constants for WiFi Security Analyzer.
"""

# ── Tool Metadata ────────────────────────────────────────────────────────────
TOOL_NAME    = "WiFi Security Analyzer"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR  = "Security Assessment Tool"

BANNER = r"""
 ██╗    ██╗ ██╗███████╗██╗    ███████╗███████╗ ██████╗
 ██║    ██║ ██║██╔════╝██║    ██╔════╝██╔════╝██╔════╝
 ██║ █╗ ██║ ██║█████╗  ██║    ███████╗█████╗  ██║
 ██║███╗██║ ██║██╔══╝  ██║    ╚════██║██╔══╝  ██║
 ╚███╔███╔╝ ██║██║     ██║    ███████║███████╗╚██████╗
  ╚══╝╚══╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝
          ███████╗███████╗ ██████╗
          ██╔════╝██╔════╝██╔════╝
          ███████╗█████╗  ██║
          ╚════██║██╔══╝  ██║
          ███████║███████╗╚██████╗
          ╚══════╝╚══════╝ ╚═════╝
      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
"""

ETHICS_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         ⚠  ETHICAL USE NOTICE  ⚠                           ║
║                                                                              ║
║  This tool is intended for AUTHORIZED security assessment only.              ║
║  Do NOT use on networks without explicit written permission.                 ║
║  Unauthorized interception of wireless communications is illegal.            ║
║  The authors accept no liability for misuse of this tool.                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ── Scan Defaults ────────────────────────────────────────────────────────────
DEFAULT_INTERFACE    = "wlan0"
DEFAULT_SCAN_TIMEOUT = 15          # seconds
OUTPUT_DIR           = "output"
LOG_DIR              = "logs"
HISTORY_FILE         = "output/scan_history.json"

# ── Risk Score Weights (must sum to 1.0) ─────────────────────────────────────
WEIGHT_ENCRYPTION   = 0.40
WEIGHT_CONFIG       = 0.30
WEIGHT_SIGNAL       = 0.15
WEIGHT_ROGUE        = 0.15

# ── Encryption scoring (raw penalty, 0–100; higher = worse) ──────────────────
ENCRYPTION_SCORES: dict[str, int] = {
    "OPEN":  100,
    "WEP":   90,
    "WPA":   50,
    "WPA2":  25,
    "WPA3":  0,
    "UNKNOWN": 60,
}

# ── Known default/vendor SSID prefixes ───────────────────────────────────────
DEFAULT_SSID_PREFIXES: list[str] = [
    "tp-link", "tplink", "netgear", "dlink", "d-link",
    "linksys", "asus", "belkin", "jiofiber", "jio",
    "airtel", "bsnl", "xfinity", "spectrum", "att",
    "default", "home", "router", "wifi", "wireless",
    "192.168", "admin", "guest", "android ap",
]

# ── Signal thresholds (dBm) ───────────────────────────────────────────────────
SIGNAL_STRONG_THRESHOLD = -40   # Unusually strong → potential leakage concern
SIGNAL_WEAK_THRESHOLD   = -80   # Very weak → low leakage risk

# ── PDF Report ───────────────────────────────────────────────────────────────
PDF_COMPANY_NAME = "WiFi Security Analyzer"
PDF_LOGO_TEXT    = "WSA"
