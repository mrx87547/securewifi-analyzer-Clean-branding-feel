"""
Shared utility functions for WiFi Security Analyzer.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import unicodedata
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)

MAX_COMMAND_TIMEOUT = 300
MAX_SSID_CHARS = 64
MAX_JSON_BYTES = 10 * 1024 * 1024

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")


class InputValidationError(ValueError):
    """Raised when user-controlled input is unsafe or invalid."""


class JsonLogFormatter(logging.Formatter):
    """Small structured JSON formatter for machine-readable diagnostics."""

    _standard_attrs: ClassVar[set[str]] = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in self._standard_attrs and _is_json_safe(value)
        }
        if extras:
            payload["context"] = extras

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def _is_json_safe(value: Any) -> bool:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True


def check_tool(tool: str) -> bool:
    """Return True when a trusted-looking executable name exists on PATH."""
    if not isinstance(tool, str) or not _TOOL_RE.fullmatch(tool):
        logger.warning("Rejected invalid tool name", extra={"event": "tool_invalid"})
        return False
    return shutil.which(tool) is not None


def require_tool(tool: str) -> None:
    """Raise EnvironmentError if a required executable is unavailable."""
    if not check_tool(tool):
        raise OSError(f"Required system tool '{tool}' was not found on PATH.")


def check_root() -> bool:
    """Return True when the process has administrator/root privileges."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # pragma: no cover - defensive Windows API fallback
            return False

    return False


def validate_interface_name(interface: str) -> str:
    """Validate a wireless interface name before passing it to OS tools."""
    if not isinstance(interface, str):
        raise InputValidationError("Interface name must be a string.")

    candidate = interface.strip()
    if not _INTERFACE_RE.fullmatch(candidate):
        raise InputValidationError(
            "Interface names may contain only letters, numbers, '.', '_', ':', '@', "
            "and '-' and must not start with punctuation."
        )
    return candidate


def validate_timeout(timeout: int, *, min_seconds: int = 1, max_seconds: int = MAX_COMMAND_TIMEOUT) -> int:
    """Validate a timeout/duration value used for external scan commands."""
    try:
        value = int(timeout)
    except (TypeError, ValueError) as exc:
        raise InputValidationError("Timeout must be an integer number of seconds.") from exc

    if value < min_seconds or value > max_seconds:
        raise InputValidationError(f"Timeout must be between {min_seconds} and {max_seconds} seconds.")
    return value


def run_command(
    cmd: Sequence[str],
    timeout: int = 30,
    capture_stderr: bool = False,
) -> str | None:
    """Execute an external command safely and return decoded stdout.

    The command is always executed with ``shell=False`` and validated as an argv
    sequence. This prevents shell injection while still allowing trusted scanner
    binaries such as ``iw``, ``iwlist``, and ``nmcli`` to run.
    """
    command = _validate_command(cmd)
    bounded_timeout = validate_timeout(timeout)
    stderr_dest = subprocess.STDOUT if capture_stderr else subprocess.PIPE
    started = time.perf_counter()

    try:
        # Security boundary: command is validated argv, shell=False, bounded timeout.
        result = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=stderr_dest,
            timeout=bounded_timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=_command_environment(),
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Command timed out",
            extra={"event": "command_timeout", "command": command[0], "timeout": bounded_timeout},
        )
        return None
    except FileNotFoundError:
        logger.error("Binary not found", extra={"event": "command_missing", "command": command[0]})
        return None
    except OSError as exc:
        logger.error(
            "OS error while running command",
            extra={"event": "command_os_error", "command": command[0], "error": str(exc)},
        )
        return None

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    stdout = (result.stdout or "").strip()
    stderr = "" if capture_stderr else (result.stderr or "").strip()

    logger.debug(
        "Command completed",
        extra={
            "event": "command_completed",
            "command": command[0],
            "returncode": result.returncode,
            "elapsed_ms": elapsed_ms,
        },
    )

    if result.returncode == 0:
        return stdout

    logger.debug(
        "Command exited non-zero",
        extra={
            "event": "command_failed",
            "command": command[0],
            "returncode": result.returncode,
            "stderr": stderr[:500],
        },
    )
    return stdout or None


def _validate_command(cmd: Sequence[str]) -> list[str]:
    if not isinstance(cmd, Sequence) or isinstance(cmd, (str, bytes)) or not cmd:
        raise InputValidationError("Command must be a non-empty sequence of arguments.")

    command = [str(part) for part in cmd]
    if any("\x00" in part for part in command):
        raise InputValidationError("Command arguments must not contain NUL bytes.")
    if not _TOOL_RE.fullmatch(Path(command[0]).name):
        raise InputValidationError("Command executable name is invalid.")
    return command


def _command_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    return env


def normalise_bssid(bssid: str) -> str:
    """Return a BSSID normalised to uppercase colon-separated format."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", str(bssid))
    if len(clean) == 12:
        return ":".join(clean[i : i + 2].upper() for i in range(0, 12, 2))
    return str(bssid).strip().upper()


def signal_quality_label(rssi: int) -> str:
    """Convert RSSI in dBm to a compact quality label."""
    try:
        value = int(rssi)
    except (TypeError, ValueError):
        return "Unknown"

    if value >= -50:
        return "Excellent"
    if value >= -60:
        return "Good"
    if value >= -70:
        return "Fair"
    if value >= -80:
        return "Poor"
    return "Unknown"


def timestamp_now() -> str:
    """Return a stable local timestamp string for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitise_ssid(raw: str) -> str:
    """Return a bounded printable SSID safe for reports and terminal output."""
    text = str(raw or "").replace("\r", " ").replace("\n", " ").strip()
    cleaned: list[str] = []

    for char in text:
        category = unicodedata.category(char)
        if category in {"Cf", "Cs", "Cc"}:
            continue
        if char.isprintable():
            cleaned.append(char)

    value = " ".join("".join(cleaned).split())
    if len(value) > MAX_SSID_CHARS:
        value = f"{value[: MAX_SSID_CHARS - 3]}..."
    return value


def safe_console_text(value: Any, *, limit: int = 500) -> str:
    """Make dynamic text safe for legacy console encodings."""
    raw = str(value or "").replace("\r", " ").replace("\n", " ")
    text = "".join(
        char for char in raw if unicodedata.category(char) not in {"Cf", "Cs", "Cc"} and char.isprintable()
    ).strip()
    if len(text) > limit:
        text = f"{text[: limit - 3]}..."
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def ensure_dir(path: str | os.PathLike[str]) -> None:
    """Create a directory and parents if needed."""
    Path(path).mkdir(parents=True, exist_ok=True)


def unique_filename(directory: str | os.PathLike[str], base: str, ext: str) -> str:
    """Generate a timestamped filename with microsecond precision."""
    ensure_dir(directory)
    suffix = ext if ext.startswith(".") else f".{ext}"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return str(Path(directory) / f"{base}_{ts}{suffix}")


def atomic_write_text(path: str | os.PathLike[str], content: str, *, mode: int = 0o600) -> None:
    """Write text atomically to avoid partial/corrupt report files."""
    target = Path(path)
    ensure_dir(target.parent if target.parent != Path("") else Path("."))

    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
        _chmod_best_effort(target, mode)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        finally:
            raise


def load_json_file(path: str | os.PathLike[str], *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Load a bounded JSON file and reject oversized inputs."""
    source = Path(path)
    if source.suffix.lower() != ".json":
        raise InputValidationError("Only JSON report files can be loaded.")
    if not source.exists() or not source.is_file():
        raise InputValidationError(f"JSON file not found: {source}")
    if source.stat().st_size > max_bytes:
        raise InputValidationError(f"JSON file is too large: {source}")

    with source.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def setup_logging(log_dir: str = "logs", level: int = logging.INFO) -> None:
    """Configure structured file logging and warning-level console diagnostics."""
    ensure_dir(log_dir)
    log_path = Path(log_dir) / f"wsa_{datetime.now().strftime('%Y%m%d')}.log"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(JsonLogFormatter())
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    console_handler.setLevel(logging.WARNING)

    root.addHandler(file_handler)
    root.addHandler(console_handler)
    _chmod_best_effort(log_path, 0o600)

    logger.info("Logging initialised", extra={"event": "logging_initialised", "path": str(log_path)})


def _chmod_best_effort(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(mode)
    except OSError:
        logger.debug("Unable to set file permissions", extra={"event": "chmod_failed", "path": str(path)})
