"""
scanner/parser.py
Parses raw stdout from iw, iwlist, and nmcli into structured network dicts.
"""

import re
import logging
from typing import Optional
from utils.helpers import normalise_bssid, sanitise_ssid

logger = logging.getLogger(__name__)


# ── Shared data model ─────────────────────────────────────────────────────────

def _empty_network() -> dict:
    """Return a blank network record with all expected keys initialised."""
    return {
        "ssid":       "<hidden>",
        "bssid":      "00:00:00:00:00:00",
        "signal":     -100,
        "channel":    0,
        "frequency":  0.0,
        "encryption": "UNKNOWN",
        "hidden":     False,
        "wps":        False,
        "vendor":     "",
        "raw_caps":   [],
    }


# ── iw dev <iface> scan ───────────────────────────────────────────────────────

def parse_iw_scan(raw: str) -> list[dict]:
    """Parse the output of `iw dev <iface> scan` into a list of networks.

    Args:
        raw: Raw stdout string from the iw scan command.

    Returns:
        List of network dicts with normalised fields.
    """
    networks: list[dict] = []
    if not raw:
        return networks

    # Split into per-BSS blocks
    blocks = re.split(r"(?=BSS [0-9a-fA-F:]{17})", raw)

    for block in blocks:
        if not block.strip():
            continue
        net = _empty_network()

        # BSSID
        m = re.search(r"BSS ([0-9a-fA-F:]{17})", block)
        if m:
            net["bssid"] = normalise_bssid(m.group(1))

        # SSID (may be absent for hidden networks)
        m = re.search(r"SSID:\s*(.+)", block)
        if m:
            raw_ssid = sanitise_ssid(m.group(1))
            if raw_ssid:
                net["ssid"]   = raw_ssid
                net["hidden"] = False
            else:
                net["ssid"]   = "<hidden>"
                net["hidden"] = True
        else:
            net["hidden"] = True

        # Signal
        m = re.search(r"signal:\s*([-\d.]+)\s*dBm", block)
        if m:
            net["signal"] = int(float(m.group(1)))

        # Frequency / Channel
        m = re.search(r"freq:\s*(\d+)", block)
        if m:
            freq_mhz = int(m.group(1))
            net["frequency"] = round(freq_mhz / 1000, 3)
            net["channel"]   = _freq_to_channel(freq_mhz)

        # Encryption — check capability lines
        cap_lines: list[str] = []
        for line in block.splitlines():
            stripped = line.strip().lower()
            if any(k in stripped for k in ("rsn", "wpa", "privacy", "wps", "capability")):
                cap_lines.append(line.strip())
        net["raw_caps"]   = cap_lines
        net["encryption"] = _derive_encryption_iw(block)

        # WPS
        if re.search(r"WPS:", block, re.IGNORECASE):
            net["wps"] = True

        networks.append(net)
        logger.debug("iw parsed: %s  enc=%s  sig=%d", net["ssid"], net["encryption"], net["signal"])

    return networks


def _derive_encryption_iw(block: str) -> str:
    """Infer encryption type from an iw BSS block.

    Args:
        block: Raw text of a single BSS block.

    Returns:
        Encryption label: OPEN | WEP | WPA | WPA2 | WPA3.
    """
    has_privacy = bool(re.search(r"capability:.*?Privacy", block, re.IGNORECASE))
    has_rsn     = bool(re.search(r"RSN:", block, re.IGNORECASE))
    has_wpa     = bool(re.search(r"\* Version: 1", block) or re.search(r"WPA\b", block, re.IGNORECASE))
    has_wpa3    = bool(re.search(r"SAE|OWE|Suite-B", block, re.IGNORECASE))

    if has_wpa3:
        return "WPA3"
    if has_rsn:
        return "WPA2"
    if has_wpa:
        return "WPA"
    if has_privacy:
        return "WEP"
    return "OPEN"


def _freq_to_channel(freq_mhz: int) -> int:
    """Convert a frequency in MHz to a WiFi channel number.

    Args:
        freq_mhz: Frequency in megahertz.

    Returns:
        Channel number, or 0 if not recognised.
    """
    if 2412 <= freq_mhz <= 2484:
        return (freq_mhz - 2412) // 5 + 1
    if 5180 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:   # 6 GHz (Wi-Fi 6E)
        return (freq_mhz - 5955) // 5 + 1
    return 0


# ── iwlist <iface> scanning ───────────────────────────────────────────────────

def parse_iwlist_scan(raw: str) -> list[dict]:
    """Parse the output of `iwlist <iface> scanning` into a list of networks.

    Args:
        raw: Raw stdout string from the iwlist command.

    Returns:
        List of network dicts.
    """
    networks: list[dict] = []
    if not raw:
        return networks

    blocks = re.split(r"Cell \d+ - ", raw)
    for block in blocks[1:]:          # first split is empty header
        net = _empty_network()

        m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", block)
        if m:
            net["bssid"] = normalise_bssid(m.group(1))

        m = re.search(r'ESSID:"([^"]*)"', block)
        if m:
            raw_ssid = sanitise_ssid(m.group(1))
            net["ssid"]   = raw_ssid if raw_ssid else "<hidden>"
            net["hidden"] = not bool(raw_ssid)

        m = re.search(r"Signal level=([-\d]+)\s*dBm", block)
        if m:
            net["signal"] = int(m.group(1))

        m = re.search(r"Channel:(\d+)", block)
        if m:
            net["channel"] = int(m.group(1))

        m = re.search(r"Frequency:([\d.]+)", block)
        if m:
            net["frequency"] = float(m.group(1))

        net["encryption"] = _derive_encryption_iwlist(block)

        networks.append(net)
        logger.debug("iwlist parsed: %s", net["ssid"])

    return networks


def _derive_encryption_iwlist(block: str) -> str:
    """Infer encryption from an iwlist cell block.

    Args:
        block: Raw text of a single iwlist Cell block.

    Returns:
        Encryption label.
    """
    if re.search(r"Encryption key:off", block, re.IGNORECASE):
        return "OPEN"
    if re.search(r"WPA3|SAE", block, re.IGNORECASE):
        return "WPA3"
    if re.search(r"WPA2|RSN", block, re.IGNORECASE):
        return "WPA2"
    if re.search(r"WPA\b", block, re.IGNORECASE):
        return "WPA"
    if re.search(r"Encryption key:on", block, re.IGNORECASE):
        return "WEP"
    return "UNKNOWN"


# ── nmcli dev wifi ────────────────────────────────────────────────────────────

def parse_nmcli_scan(raw: str) -> list[dict]:
    """Parse the output of `nmcli -f ALL dev wifi list` into networks.

    nmcli column headers (with --terse are colon-separated).  We use the
    human-readable tabular format and parse it with column offsets detected
    from the header line.

    Args:
        raw: Raw stdout from nmcli.

    Returns:
        List of network dicts.
    """
    networks: list[dict] = []
    if not raw:
        return networks

    lines = raw.splitlines()
    if len(lines) < 2:
        return networks

    # Try terse format first (nmcli -t -f ...)
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 8:
            net = _parse_nmcli_terse_line(parts)
            if net:
                networks.append(net)

    if networks:
        return networks

    # Fall back: try to parse columnar format
    return _parse_nmcli_columnar(lines)


def _parse_nmcli_terse_line(parts: list[str]) -> Optional[dict]:
    """Parse a single terse nmcli line (colon-separated).

    Expected field order for `nmcli -t -f IN-USE,BSSID,SSID,MODE,CHAN,FREQ,
    RATE,SIGNAL,BARS,SECURITY dev wifi list`:

        IN-USE:BSSID:SSID:MODE:CHAN:FREQ:RATE:SIGNAL:BARS:SECURITY
    """
    try:
        net = _empty_network()
        # parts[1] = BSSID, parts[2] = SSID, parts[4] = CHAN, parts[7] = SIGNAL
        # parts[9] = SECURITY
        bssid = parts[1].replace("\\:", ":").strip()
        if bssid:
            net["bssid"] = normalise_bssid(bssid)

        ssid = sanitise_ssid(parts[2]) if len(parts) > 2 else ""
        net["ssid"]   = ssid if ssid else "<hidden>"
        net["hidden"] = not bool(ssid)

        if len(parts) > 4:
            try:
                net["channel"] = int(parts[4])
            except ValueError:
                pass

        if len(parts) > 7:
            try:
                # nmcli SIGNAL is 0-100; convert roughly to dBm
                sig_pct = int(parts[7])
                net["signal"] = _percent_to_dbm(sig_pct)
            except ValueError:
                pass

        if len(parts) > 9:
            net["encryption"] = _derive_encryption_nmcli(parts[9])

        return net
    except (IndexError, ValueError) as exc:
        logger.debug("Failed to parse nmcli terse line: %s", exc)
        return None


def _parse_nmcli_columnar(lines: list[str]) -> list[dict]:
    """Fallback columnar parser for nmcli output.

    Args:
        lines: All stdout lines from nmcli.

    Returns:
        List of network dicts.
    """
    networks = []
    header = lines[0].lower()
    col_ssid    = _col_offset(header, "ssid")
    col_bssid   = _col_offset(header, "bssid")
    col_signal  = _col_offset(header, "signal")
    col_chan    = _col_offset(header, "chan")
    col_sec     = _col_offset(header, "security")

    for line in lines[1:]:
        if not line.strip():
            continue
        net = _empty_network()
        net["ssid"]       = sanitise_ssid(_col_value(line, col_ssid, col_bssid)) or "<hidden>"
        net["hidden"]     = net["ssid"] == "<hidden>"
        bssid_raw         = _col_value(line, col_bssid, col_signal)
        net["bssid"]      = normalise_bssid(bssid_raw) if bssid_raw.strip() else net["bssid"]
        sig_raw           = _col_value(line, col_signal, col_chan).strip()
        net["signal"]     = _percent_to_dbm(int(sig_raw)) if sig_raw.isdigit() else -100
        chan_raw          = _col_value(line, col_chan, col_sec).strip()
        net["channel"]    = int(chan_raw) if chan_raw.isdigit() else 0
        sec_raw           = line[col_sec:].strip() if col_sec else ""
        net["encryption"] = _derive_encryption_nmcli(sec_raw)
        networks.append(net)

    return networks


def _col_offset(header: str, name: str) -> int:
    """Return the character offset of a column name in a header string."""
    idx = header.find(name)
    return idx if idx >= 0 else 0


def _col_value(line: str, start: int, end: int) -> str:
    """Slice a fixed-width column value from a line."""
    return line[start:end].strip() if end > start else line[start:].strip()


def _derive_encryption_nmcli(security_field: str) -> str:
    """Map nmcli SECURITY field to a normalised encryption label.

    Args:
        security_field: Raw security string from nmcli (e.g. "WPA2 802.1X").

    Returns:
        Encryption label.
    """
    s = security_field.upper()
    if not s or s in ("--", "NONE", ""):
        return "OPEN"
    if "WPA3" in s or "SAE" in s:
        return "WPA3"
    if "WPA2" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    return "UNKNOWN"


def _percent_to_dbm(pct: int) -> int:
    """Convert a 0-100 signal quality percentage to an approximate dBm value.

    Formula: dBm ≈ (pct / 2) - 100
    """
    return int((max(0, min(100, pct)) / 2) - 100)
