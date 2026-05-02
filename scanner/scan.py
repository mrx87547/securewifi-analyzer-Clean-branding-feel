"""
scanner/scan.py
Executes Linux wireless scan commands (iw / iwlist / nmcli) and returns
parsed network lists.  Falls back gracefully when tools are unavailable.
"""

import logging
import time
from typing import Optional

from utils.helpers import run_command, check_tool, check_root
from scanner.parser import parse_iw_scan, parse_iwlist_scan, parse_nmcli_scan
from config.settings import DEFAULT_SCAN_TIMEOUT

logger = logging.getLogger(__name__)


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_networks(
    interface: str = "wlan0",
    timeout: int = DEFAULT_SCAN_TIMEOUT,
) -> list[dict]:
    """Scan for nearby WiFi networks using the best available tool.

    Tries tools in order: iw → iwlist → nmcli.
    If none succeeds, returns a demo dataset for offline testing.

    Args:
        interface: Wireless interface name (e.g. "wlan0").
        timeout:   Maximum seconds to wait for a scan.

    Returns:
        List of normalised network dicts.
    """
    logger.info("Starting WiFi scan on interface: %s", interface)

    # ── Try iw ────────────────────────────────────────────────────────────────
    if check_tool("iw"):
        networks = _scan_with_iw(interface, timeout)
        if networks:
            logger.info("iw scan returned %d networks", len(networks))
            return _deduplicate(networks)

    # ── Try iwlist ────────────────────────────────────────────────────────────
    if check_tool("iwlist"):
        networks = _scan_with_iwlist(interface, timeout)
        if networks:
            logger.info("iwlist scan returned %d networks", len(networks))
            return _deduplicate(networks)

    # ── Try nmcli ─────────────────────────────────────────────────────────────
    if check_tool("nmcli"):
        networks = _scan_with_nmcli(interface, timeout)
        if networks:
            logger.info("nmcli scan returned %d networks", len(networks))
            return _deduplicate(networks)

    # ── Offline / demo fallback ────────────────────────────────────────────────
    logger.warning("No scan tools produced results; using demo dataset.")
    return _demo_networks()


# ── iw ────────────────────────────────────────────────────────────────────────

def _scan_with_iw(interface: str, timeout: int) -> list[dict]:
    """Run `iw dev <iface> scan` and parse results.

    Args:
        interface: Wireless interface.
        timeout:   Command timeout in seconds.

    Returns:
        Parsed network list, possibly empty.
    """
    if not check_root():
        logger.warning("iw scan requires root privileges; attempting anyway.")

    # Trigger a fresh scan
    raw = run_command(["iw", "dev", interface, "scan"], timeout=timeout, capture_stderr=True)
    if not raw:
        # Some drivers need an explicit link-up first
        run_command(["ip", "link", "set", interface, "up"], timeout=5)
        time.sleep(1)
        raw = run_command(["iw", "dev", interface, "scan"], timeout=timeout, capture_stderr=True)

    if not raw:
        logger.debug("iw scan produced no output for %s", interface)
        return []

    return parse_iw_scan(raw)


# ── iwlist ────────────────────────────────────────────────────────────────────

def _scan_with_iwlist(interface: str, timeout: int) -> list[dict]:
    """Run `iwlist <iface> scanning` and parse results.

    Args:
        interface: Wireless interface.
        timeout:   Command timeout in seconds.

    Returns:
        Parsed network list, possibly empty.
    """
    raw = run_command(["iwlist", interface, "scanning"], timeout=timeout, capture_stderr=True)
    if not raw or "No scan results" in raw:
        logger.debug("iwlist returned no results for %s", interface)
        return []
    return parse_iwlist_scan(raw)


# ── nmcli ─────────────────────────────────────────────────────────────────────

def _scan_with_nmcli(interface: str, timeout: int) -> list[dict]:
    """Run `nmcli device wifi rescan` then `nmcli -t dev wifi list`.

    Args:
        interface: Wireless interface.
        timeout:   Command timeout in seconds.

    Returns:
        Parsed network list, possibly empty.
    """
    # Trigger rescan (ignore errors)
    run_command(["nmcli", "device", "wifi", "rescan", "ifname", interface], timeout=10)
    time.sleep(2)

    raw = run_command(
        ["nmcli", "-t", "-f",
         "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
         "dev", "wifi", "list"],
        timeout=timeout,
    )
    if not raw:
        return []
    return parse_nmcli_scan(raw)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _deduplicate(networks: list[dict]) -> list[dict]:
    """Remove duplicate BSSIDs, keeping the strongest signal.

    Args:
        networks: Raw list of network dicts.

    Returns:
        De-duplicated list ordered by signal strength (strongest first).
    """
    best: dict[str, dict] = {}
    for net in networks:
        bssid = net["bssid"]
        if bssid not in best or net["signal"] > best[bssid]["signal"]:
            best[bssid] = net
    return sorted(best.values(), key=lambda n: n["signal"], reverse=True)


# ── Demo Dataset ──────────────────────────────────────────────────────────────

def _demo_networks() -> list[dict]:
    """Return a realistic demo dataset for testing without a wireless adapter.

    Returns:
        Hardcoded list of network dicts covering all encryption types.
    """
    return [
        {
            "ssid": "CoffeeShop_Free",
            "bssid": "AA:BB:CC:11:22:33",
            "signal": -45,
            "channel": 6,
            "frequency": 2.437,
            "encryption": "OPEN",
            "hidden": False,
            "wps": False,
            "vendor": "",
            "raw_caps": [],
        },
        {
            "ssid": "TP-Link_2D4E",
            "bssid": "AA:BB:CC:11:22:44",
            "signal": -55,
            "channel": 1,
            "frequency": 2.412,
            "encryption": "WPA2",
            "hidden": False,
            "wps": True,
            "vendor": "TP-Link",
            "raw_caps": [],
        },
        {
            "ssid": "OldOfficeNetwork",
            "bssid": "AA:BB:CC:11:22:55",
            "signal": -60,
            "channel": 11,
            "frequency": 2.462,
            "encryption": "WEP",
            "hidden": False,
            "wps": False,
            "vendor": "",
            "raw_caps": [],
        },
        {
            "ssid": "HomeNet_5G",
            "bssid": "AA:BB:CC:11:22:66",
            "signal": -65,
            "channel": 36,
            "frequency": 5.180,
            "encryption": "WPA3",
            "hidden": False,
            "wps": False,
            "vendor": "",
            "raw_caps": [],
        },
        {
            "ssid": "JioFiber_Guest",
            "bssid": "AA:BB:CC:11:22:77",
            "signal": -70,
            "channel": 6,
            "frequency": 2.437,
            "encryption": "WPA2",
            "hidden": False,
            "wps": True,
            "vendor": "Jio",
            "raw_caps": [],
        },
        {
            "ssid": "<hidden>",
            "bssid": "AA:BB:CC:11:22:88",
            "signal": -75,
            "channel": 11,
            "frequency": 2.462,
            "encryption": "WPA2",
            "hidden": True,
            "wps": False,
            "vendor": "",
            "raw_caps": [],
        },
        {
            "ssid": "CoffeeShop_Free",   # Duplicate SSID — potential rogue AP
            "bssid": "FF:EE:DD:33:22:11",
            "signal": -50,
            "channel": 6,
            "frequency": 2.437,
            "encryption": "OPEN",
            "hidden": False,
            "wps": False,
            "vendor": "",
            "raw_caps": [],
        },
        {
            "ssid": "Netgear_ABCD",
            "bssid": "AA:BB:CC:11:22:99",
            "signal": -80,
            "channel": 1,
            "frequency": 2.412,
            "encryption": "WPA",
            "hidden": False,
            "wps": True,
            "vendor": "Netgear",
            "raw_caps": [],
        },
    ]
