"""
Wireless scan orchestration.

The scanner executes trusted Linux wireless tools with argv-only subprocess
calls, validates user-controlled interface names, and never fabricates live scan
results unless demo mode is explicitly requested.
"""

from __future__ import annotations

import logging
import time

from config.settings import DEFAULT_SCAN_TIMEOUT
from scanner.parser import parse_iw_scan, parse_iwlist_scan, parse_nmcli_scan
from utils.helpers import (
    check_root,
    check_tool,
    run_command,
    validate_interface_name,
    validate_timeout,
)

logger = logging.getLogger(__name__)


def scan_networks(
    interface: str = "wlan0",
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    *,
    demo_mode: bool = False,
) -> list[dict]:
    """Scan for nearby WiFi networks using the best available tool.

    Tries tools in order: ``iw``, ``iwlist``, then ``nmcli``. If no tool can
    produce results, an empty list is returned. Demo data is returned only when
    ``demo_mode`` is explicitly enabled by the caller.
    """
    safe_interface = validate_interface_name(interface)
    safe_timeout = validate_timeout(timeout)

    logger.info(
        "Starting WiFi scan",
        extra={
            "event": "scan_started",
            "interface": safe_interface,
            "timeout": safe_timeout,
            "demo_mode": demo_mode,
        },
    )

    if demo_mode:
        logger.warning("Using explicit demo dataset", extra={"event": "scan_demo_mode"})
        return _deduplicate(_demo_networks())

    attempts: list[tuple[str, list[dict]]] = []

    if check_tool("iw"):
        networks = _scan_with_iw(safe_interface, safe_timeout)
        attempts.append(("iw", networks))
        if networks:
            return _finalise_scan("iw", networks)

    if check_tool("iwlist"):
        networks = _scan_with_iwlist(safe_interface, safe_timeout)
        attempts.append(("iwlist", networks))
        if networks:
            return _finalise_scan("iwlist", networks)

    if check_tool("nmcli"):
        networks = _scan_with_nmcli(safe_interface, safe_timeout)
        attempts.append(("nmcli", networks))
        if networks:
            return _finalise_scan("nmcli", networks)

    logger.error(
        "No wireless scan tool produced results",
        extra={
            "event": "scan_no_results",
            "interface": safe_interface,
            "attempts": [{"tool": tool, "count": len(rows)} for tool, rows in attempts],
        },
    )
    return []


def _scan_with_iw(interface: str, timeout: int) -> list[dict]:
    """Run ``iw dev <iface> scan`` and parse results."""
    if not check_root():
        logger.warning(
            "iw scans usually require root privileges",
            extra={"event": "scan_privilege_warning", "tool": "iw", "interface": interface},
        )

    raw = run_command(["iw", "dev", interface, "scan"], timeout=timeout, capture_stderr=True)
    if not raw:
        logger.debug("iw scan produced no parseable output", extra={"event": "scan_empty", "tool": "iw"})
        return []
    return parse_iw_scan(raw)


def _scan_with_iwlist(interface: str, timeout: int) -> list[dict]:
    """Run ``iwlist <iface> scanning`` and parse results."""
    raw = run_command(["iwlist", interface, "scanning"], timeout=timeout, capture_stderr=True)
    if not raw or "No scan results" in raw:
        logger.debug(
            "iwlist returned no results",
            extra={"event": "scan_empty", "tool": "iwlist", "interface": interface},
        )
        return []
    return parse_iwlist_scan(raw)


def _scan_with_nmcli(interface: str, timeout: int) -> list[dict]:
    """Run ``nmcli device wifi list`` and parse terse output."""
    raw = run_command(
        [
            "nmcli",
            "-t",
            "--escape",
            "yes",
            "-f",
            "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "yes",
        ],
        timeout=timeout,
    )
    if not raw:
        return []
    return parse_nmcli_scan(raw)


def _finalise_scan(tool: str, networks: list[dict]) -> list[dict]:
    deduped = _deduplicate(networks)
    logger.info(
        "Wireless scan completed",
        extra={"event": "scan_completed", "tool": tool, "network_count": len(deduped)},
    )
    return deduped


def _deduplicate(networks: list[dict]) -> list[dict]:
    """Remove duplicate BSSIDs, keeping the strongest signal."""
    best: dict[str, dict] = {}
    for network in networks:
        bssid = str(network.get("bssid", "")).upper()
        if not bssid or bssid == "00:00:00:00:00:00":
            continue

        signal = _safe_signal(network.get("signal", -100))
        network["signal"] = signal
        if bssid not in best or signal > _safe_signal(best[bssid].get("signal", -100)):
            best[bssid] = network

    return sorted(best.values(), key=lambda item: _safe_signal(item.get("signal", -100)), reverse=True)


def _safe_signal(value: object) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return -100


def _demo_networks() -> list[dict]:
    """Return a realistic demo dataset for tests and offline demonstrations."""
    time.sleep(0.05)
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
            "ssid": "CoffeeShop_Free",
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
