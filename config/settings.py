"""
Global configuration and constants for WiFi Security Analyzer.
"""

from __future__ import annotations

TOOL_NAME = "WiFi Security Analyzer"
TOOL_VERSION = "1.1.0"
TOOL_AUTHOR = "Security Assessment Tool"

BANNER = r"""
 __        ___ _____ ___   ____                 
 \ \      / (_)  ___|_ _| / ___|  ___  ___     
  \ \ /\ / /| | |_   | |  \___ \ / _ \/ __|    
   \ V  V / | |  _|  | |   ___) |  __/ (__     
    \_/\_/  |_|_|   |___| |____/ \___|\___|    

        WiFi Security Analyzer
"""

ETHICS_DISCLAIMER = """
AUTHORIZED USE NOTICE

This tool is intended for authorized security assessment only.
Do not use it on networks without explicit written permission.
Unauthorized interception of wireless communications is illegal.
"""

DEFAULT_INTERFACE = "wlan0"
DEFAULT_SCAN_TIMEOUT = 15
MAX_SCAN_TIMEOUT = 300
OUTPUT_DIR = "output"
LOG_DIR = "logs"
HISTORY_FILE = "output/scan_history.json"
MAX_HISTORY_ENTRIES = 100

WEIGHT_ENCRYPTION = 0.40
WEIGHT_CONFIG = 0.30
WEIGHT_SIGNAL = 0.15
WEIGHT_ROGUE = 0.15

ENCRYPTION_SCORES: dict[str, int] = {
    "OPEN": 100,
    "WEP": 90,
    "WPA": 50,
    "WPA2": 25,
    "WPA3": 0,
    "UNKNOWN": 60,
}

DEFAULT_SSID_PREFIXES: list[str] = [
    "tp-link",
    "tplink",
    "netgear",
    "dlink",
    "d-link",
    "linksys",
    "asus",
    "belkin",
    "jiofiber",
    "jio",
    "airtel",
    "bsnl",
    "xfinity",
    "spectrum",
    "att",
    "default",
    "home",
    "router",
    "wifi",
    "wireless",
    "192.168",
    "admin",
    "guest",
    "android ap",
]

SIGNAL_STRONG_THRESHOLD = -40
SIGNAL_WEAK_THRESHOLD = -80

PDF_COMPANY_NAME = "WiFi Security Analyzer"
PDF_LOGO_TEXT = "WSA"
