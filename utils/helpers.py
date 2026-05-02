"""
utils/helpers.py
Shared utility functions used across the WiFi Security Analyzer.
"""

import os
import re
import shutil
import logging
import subprocess
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ── Tool Availability ─────────────────────────────────────────────────────────

def check_tool(tool: str) -> bool:
    """Check whether a system binary is available in PATH.

    Args:
        tool: Name of the binary to look up (e.g. "iw", "nmcli").

    Returns:
        True if the tool is found, False otherwise.
    """
    return shutil.which(tool) is not None


def require_tool(tool: str) -> None:
    """Raise EnvironmentError if a required tool is not available.

    Args:
        tool: Name of the required binary.

    Raises:
        EnvironmentError: When the binary cannot be found in PATH.
    """
    if not check_tool(tool):
        raise EnvironmentError(
            f"Required system tool '{tool}' not found. "
            f"Install it with: sudo apt install {tool}"
        )


def check_root() -> bool:
    """Return True when the process is running as root (UID 0)."""
    return os.geteuid() == 0


# ── Shell Execution ───────────────────────────────────────────────────────────

def run_command(
    cmd: list[str],
    timeout: int = 30,
    capture_stderr: bool = False,
) -> Optional[str]:
    """Execute a shell command and return its stdout.

    Args:
        cmd:            Command and arguments as a list.
        timeout:        Maximum seconds to wait for the process.
        capture_stderr: When True, stderr is merged into stdout.

    Returns:
        Decoded stdout string, or None on failure.
    """
    stderr_dest = subprocess.STDOUT if capture_stderr else subprocess.DEVNULL
    try:
        result = subprocess.run(
            cmd,
            capture_output=not capture_stderr,
            stdout=subprocess.PIPE if not capture_stderr else None,
            stderr=stderr_dest,
            timeout=timeout,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logger.debug("Command %s exited with code %d", cmd, result.returncode)
        return result.stdout.strip() if result.stdout else None
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(cmd))
        return None
    except FileNotFoundError:
        logger.error("Binary not found: %s", cmd[0])
        return None
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Unexpected error running %s: %s", cmd, exc)
        return None


# ── String / Network Helpers ──────────────────────────────────────────────────

def normalise_bssid(bssid: str) -> str:
    """Return a BSSID normalised to uppercase colon-separated format.

    Args:
        bssid: Raw BSSID string (any separator).

    Returns:
        Formatted BSSID, e.g. "AA:BB:CC:DD:EE:FF".
    """
    clean = re.sub(r"[^0-9A-Fa-f]", "", bssid)
    if len(clean) == 12:
        return ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
    return bssid.upper()


def signal_quality_label(rssi: int) -> str:
    """Convert an RSSI value to a human-readable quality label.

    Args:
        rssi: Signal level in dBm (typically negative).

    Returns:
        One of "Excellent", "Good", "Fair", "Poor", or "Unknown".
    """
    if rssi >= -50:
        return "Excellent"
    if rssi >= -60:
        return "Good"
    if rssi >= -70:
        return "Fair"
    if rssi >= -80:
        return "Poor"
    return "Unknown"


def timestamp_now() -> str:
    """Return a formatted timestamp string for the current moment."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitise_ssid(raw: str) -> str:
    """Strip non-printable characters from an SSID string.

    Args:
        raw: Raw SSID value from a scan tool.

    Returns:
        Cleaned, printable SSID string.
    """
    return "".join(c for c in raw if c.isprintable()).strip()


# ── Directory / File Helpers ──────────────────────────────────────────────────

def ensure_dir(path: str) -> None:
    """Create a directory (and parents) if it does not already exist.

    Args:
        path: Directory path to create.
    """
    os.makedirs(path, exist_ok=True)


def unique_filename(directory: str, base: str, ext: str) -> str:
    """Generate a unique filename by appending a timestamp.

    Args:
        directory: Target directory.
        base:      Base filename without extension.
        ext:       File extension including the leading dot.

    Returns:
        Full path to a uniquely named file.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(directory, f"{base}_{ts}{ext}")


# ── Logging Setup ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str = "logs", level: int = logging.INFO) -> None:
    """Configure file and console logging for the application.

    Args:
        log_dir: Directory where log files are written.
        level:   Logging level (e.g. logging.DEBUG).
    """
    ensure_dir(log_dir)
    log_path = os.path.join(log_dir, f"wsa_{datetime.now().strftime('%Y%m%d')}.log")

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.WARNING)  # Only warnings+ to console

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    logger.info("Logging initialised → %s", log_path)
