"""
Parsers for raw stdout produced by iw, iwlist, and nmcli.
"""

from __future__ import annotations

import logging
import re

from utils.helpers import normalise_bssid, sanitise_ssid

logger = logging.getLogger(__name__)

BSSID_RE = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"


def _empty_network() -> dict:
    """Return a blank network record with all expected keys initialised."""
    return {
        "ssid": "<hidden>",
        "bssid": "00:00:00:00:00:00",
        "signal": -100,
        "channel": 0,
        "frequency": 0.0,
        "encryption": "UNKNOWN",
        "hidden": False,
        "wps": False,
        "vendor": "",
        "raw_caps": [],
    }


def parse_iw_scan(raw: str) -> list[dict]:
    """Parse ``iw dev <iface> scan`` output into normalised network dicts."""
    if not raw:
        return []

    networks: list[dict] = []
    blocks = re.split(rf"(?=^BSS {BSSID_RE})", raw, flags=re.MULTILINE)

    for block in blocks:
        if not block.strip() or not re.search(rf"^BSS {BSSID_RE}", block, re.MULTILINE):
            continue

        net = _empty_network()

        match = re.search(rf"^BSS ({BSSID_RE})", block, re.MULTILINE)
        if match:
            net["bssid"] = normalise_bssid(match.group(1))

        match = re.search(r"^[ \t]*SSID:[ \t]*(.*)$", block, re.MULTILINE)
        if match:
            ssid = sanitise_ssid(match.group(1))
            net["ssid"] = ssid if ssid else "<hidden>"
            net["hidden"] = not bool(ssid)
        else:
            net["hidden"] = True

        match = re.search(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", block, re.IGNORECASE)
        if match:
            net["signal"] = int(float(match.group(1)))

        match = re.search(r"freq:\s*(\d+)", block)
        if match:
            freq_mhz = int(match.group(1))
            net["frequency"] = round(freq_mhz / 1000, 3)
            net["channel"] = _freq_to_channel(freq_mhz)

        net["raw_caps"] = _capability_lines(block)
        net["encryption"] = _derive_encryption_iw(block)
        net["wps"] = bool(re.search(r"\bWPS\b|Wi-Fi Protected Setup", block, re.IGNORECASE))

        networks.append(net)
        logger.debug(
            "Parsed iw network",
            extra={"event": "parse_iw_network", "bssid": net["bssid"], "encryption": net["encryption"]},
        )

    return networks


def _derive_encryption_iw(block: str) -> str:
    """Infer encryption type from an iw BSS block."""
    has_privacy = bool(re.search(r"capability:.*?Privacy", block, re.IGNORECASE))
    has_rsn = bool(re.search(r"\bRSN:", block, re.IGNORECASE))
    has_wpa = bool(re.search(r"\bWPA:", block, re.IGNORECASE) or re.search(r"\* Version: 1", block))
    has_wpa3 = bool(re.search(r"\b(SAE|OWE|Suite-B)\b", block, re.IGNORECASE))

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
    """Convert a WiFi frequency in MHz to a channel number."""
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return ((freq_mhz - 2412) // 5) + 1
    if 5180 <= freq_mhz <= 5885:
        return (freq_mhz - 5000) // 5
    if freq_mhz == 5935:
        return 2
    if 5955 <= freq_mhz <= 7115:
        return ((freq_mhz - 5955) // 5) + 1
    return 0


def parse_iwlist_scan(raw: str) -> list[dict]:
    """Parse ``iwlist <iface> scanning`` output into normalised network dicts."""
    if not raw:
        return []

    networks: list[dict] = []
    blocks = re.split(r"Cell \d+\s+-\s+", raw)

    for block in blocks[1:]:
        net = _empty_network()

        match = re.search(rf"Address:\s*({BSSID_RE})", block)
        if match:
            net["bssid"] = normalise_bssid(match.group(1))

        match = re.search(r'ESSID:"([^"]*)"', block)
        if match:
            ssid = sanitise_ssid(match.group(1))
            net["ssid"] = ssid if ssid else "<hidden>"
            net["hidden"] = not bool(ssid)

        match = re.search(r"Signal level=(-?\d+)\s*dBm", block)
        if match:
            net["signal"] = int(match.group(1))

        match = re.search(r"Channel:(\d+)", block)
        if match:
            net["channel"] = int(match.group(1))

        match = re.search(r"Frequency:([\d.]+)", block)
        if match:
            net["frequency"] = float(match.group(1))

        net["raw_caps"] = _capability_lines(block)
        net["wps"] = bool(re.search(r"\bWPS\b|Wi-Fi Protected Setup", block, re.IGNORECASE))
        net["encryption"] = _derive_encryption_iwlist(block)
        networks.append(net)

    return networks


def _derive_encryption_iwlist(block: str) -> str:
    """Infer encryption from an iwlist cell block."""
    if re.search(r"Encryption key:off", block, re.IGNORECASE):
        return "OPEN"
    if re.search(r"\b(WPA3|SAE|OWE)\b", block, re.IGNORECASE):
        return "WPA3"
    if re.search(r"\b(WPA2|RSN|IEEE 802\.11i)\b", block, re.IGNORECASE):
        return "WPA2"
    if re.search(r"\bWPA\b", block, re.IGNORECASE):
        return "WPA"
    if re.search(r"Encryption key:on", block, re.IGNORECASE):
        return "WEP"
    return "UNKNOWN"


def parse_nmcli_scan(raw: str) -> list[dict]:
    """Parse terse or columnar ``nmcli device wifi list`` output."""
    if not raw:
        return []

    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return []

    networks = [_parse_nmcli_terse_line(_split_nmcli_terse(line)) for line in lines]
    parsed = [network for network in networks if network]
    if parsed:
        return parsed

    return _parse_nmcli_columnar(lines)


def _split_nmcli_terse(line: str) -> list[str]:
    """Split nmcli terse output while honoring backslash-escaped colons."""
    parts: list[str] = []
    buffer: list[str] = []
    escaped = False

    for char in line:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)

    if escaped:
        buffer.append("\\")
    parts.append("".join(buffer))
    return parts


def _parse_nmcli_terse_line(parts: list[str]) -> dict | None:
    """Parse one terse nmcli row.

    Expected order:
    IN-USE:BSSID:SSID:MODE:CHAN:FREQ:RATE:SIGNAL:BARS:SECURITY
    """
    if len(parts) < 10:
        return None

    net = _empty_network()
    bssid = parts[1].strip()
    if not re.fullmatch(BSSID_RE, bssid):
        return None

    net["bssid"] = normalise_bssid(bssid)
    ssid = sanitise_ssid(parts[2])
    net["ssid"] = ssid if ssid else "<hidden>"
    net["hidden"] = not bool(ssid)
    net["channel"] = _parse_int(parts[4], default=0)
    net["frequency"] = _parse_frequency_ghz(parts[5])
    net["signal"] = _percent_to_dbm(_parse_int(parts[7], default=0))
    net["encryption"] = _derive_encryption_nmcli(parts[9])
    return net


def _parse_nmcli_columnar(lines: list[str]) -> list[dict]:
    """Fallback parser for fixed-width nmcli output."""
    header = lines[0].lower()
    offsets = {
        "ssid": _col_offset(header, "ssid"),
        "bssid": _col_offset(header, "bssid"),
        "signal": _col_offset(header, "signal"),
        "chan": _col_offset(header, "chan"),
        "security": _col_offset(header, "security"),
    }
    if any(value < 0 for value in offsets.values()):
        return []

    networks: list[dict] = []
    for line in lines[1:]:
        net = _empty_network()
        ssid = sanitise_ssid(_col_value(line, offsets, "ssid"))
        net["ssid"] = ssid if ssid else "<hidden>"
        net["hidden"] = not bool(ssid)

        bssid = _col_value(line, offsets, "bssid")
        if re.fullmatch(BSSID_RE, bssid):
            net["bssid"] = normalise_bssid(bssid)
        else:
            continue

        net["signal"] = _percent_to_dbm(_parse_int(_col_value(line, offsets, "signal"), default=0))
        net["channel"] = _parse_int(_col_value(line, offsets, "chan"), default=0)
        net["encryption"] = _derive_encryption_nmcli(_col_value(line, offsets, "security"))
        networks.append(net)

    return networks


def _derive_encryption_nmcli(security_field: str) -> str:
    """Map nmcli SECURITY text to a normalised encryption label."""
    security = security_field.upper().strip()
    if not security or security in {"--", "NONE"}:
        return "OPEN"
    if "WPA3" in security or "SAE" in security or "OWE" in security:
        return "WPA3"
    if "WPA2" in security:
        return "WPA2"
    if "WPA" in security:
        return "WPA"
    if "WEP" in security:
        return "WEP"
    return "UNKNOWN"


def _percent_to_dbm(pct: int) -> int:
    """Convert a 0-100 signal quality percentage to approximate dBm."""
    return int((max(0, min(100, pct)) / 2) - 100)


def _capability_lines(block: str) -> list[str]:
    keywords = ("rsn", "wpa", "privacy", "wps", "capability", "encryption key")
    return [line.strip() for line in block.splitlines() if any(key in line.lower() for key in keywords)]


def _parse_int(value: str, *, default: int) -> int:
    match = re.search(r"-?\d+", value)
    return int(match.group(0)) if match else default


def _parse_frequency_ghz(value: str) -> float:
    match = re.search(r"\d+(?:\.\d+)?", value)
    if not match:
        return 0.0
    number = float(match.group(0))
    return round(number / 1000, 3) if number > 100 else round(number, 3)


def _col_offset(header: str, name: str) -> int:
    index = header.find(name)
    return index if index >= 0 else -1


def _col_value(line: str, offsets: dict[str, int], name: str) -> str:
    start = offsets[name]
    later_offsets = [offset for key, offset in offsets.items() if key != name and offset > start]
    end = min(later_offsets) if later_offsets else len(line)
    return line[start:end].strip()
