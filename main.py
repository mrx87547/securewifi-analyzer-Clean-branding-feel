#!/usr/bin/env python3
"""
WiFi Security Analyzer CLI entry point.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from analyzer.encryption import analyse_encryption
from analyzer.rogue import detect_rogue_aps
from analyzer.vulnerabilities import analyse_configuration
from config.settings import (
    BANNER,
    DEFAULT_INTERFACE,
    DEFAULT_SCAN_TIMEOUT,
    ETHICS_DISCLAIMER,
    HISTORY_FILE,
    LOG_DIR,
    MAX_HISTORY_ENTRIES,
    MAX_SCAN_TIMEOUT,
    OUTPUT_DIR,
    TOOL_NAME,
    TOOL_VERSION,
)
from reporting.report_cli import render_report
from reporting.report_json import save_json_report
from reporting.report_pdf import REPORTLAB_AVAILABLE, save_pdf_report
from risk_engine.scoring import calculate_risk_score, rank_networks
from scanner.scan import scan_networks
from utils.helpers import (
    InputValidationError,
    atomic_write_text,
    ensure_dir,
    load_json_file,
    safe_console_text,
    setup_logging,
    signal_quality_label,
    timestamp_now,
    validate_interface_name,
    validate_timeout,
)

console = Console(safe_box=True, emoji=False)
logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="wsa",
        description=f"{TOOL_NAME} v{TOOL_VERSION} - Wireless Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan --interface wlan0 --output cli
  python main.py --scan --interface wlan0 --output json
  python main.py --scan --interface wlan0 --output pdf --verbose
  python main.py --scan --output all --verbose --demo
  python main.py --history
        """,
    )

    parser.add_argument("--scan", action="store_true", help="Perform a wireless network scan")
    parser.add_argument(
        "--interface",
        "-i",
        default=DEFAULT_INTERFACE,
        type=_interface_arg,
        metavar="IFACE",
        help=f"Wireless interface to use (default: {DEFAULT_INTERFACE})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="cli",
        choices=["cli", "json", "pdf", "all"],
        help="Output format: cli | json | pdf | all (default: cli)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=_duration_arg,
        default=DEFAULT_SCAN_TIMEOUT,
        metavar="SECS",
        help=f"Scan duration in seconds (1-{MAX_SCAN_TIMEOUT}, default: {DEFAULT_SCAN_TIMEOUT})",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use built-in demo scan data instead of live wireless tools",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed per-network vulnerability panels in CLI output",
    )
    parser.add_argument("--history", action="store_true", help="Show a summary of previous scan history")
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("SCAN_A", "SCAN_B"),
        help="Compare two JSON scan reports",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    return parser


def run_analysis(interface: str, duration: int, *, demo_mode: bool = False) -> tuple[list[dict], dict]:
    """Execute the full scan and analysis pipeline."""
    safe_interface = validate_interface_name(interface)
    safe_duration = validate_timeout(duration, max_seconds=MAX_SCAN_TIMEOUT)
    scan_meta = {
        "interface": safe_interface,
        "timestamp": timestamp_now(),
        "duration": safe_duration,
        "demo_mode": demo_mode,
    }

    console.print(
        f"[cyan]Scanning on [bold]{escape(safe_interface)}[/bold]{' (demo mode)' if demo_mode else ''}...[/cyan]"
    )
    raw_networks = scan_networks(interface=safe_interface, timeout=safe_duration, demo_mode=demo_mode)

    if not raw_networks:
        console.print("[red]No networks found. Check interface, permissions, and installed scan tools.[/red]")
        return [], scan_meta

    console.print(f"[green]Found {len(raw_networks)} network(s).[/green]")
    console.print("[cyan]Detecting rogue AP indicators...[/cyan]")
    rogue_map = detect_rogue_aps(raw_networks)

    console.print("[cyan]Analysing security configurations...[/cyan]")
    analysed: list[dict] = []

    for raw in raw_networks:
        network = dict(raw)
        enc_analysis = analyse_encryption(network)
        config_findings = analyse_configuration(network)
        rogue_findings = rogue_map.get(network.get("bssid", ""), [])

        risk = calculate_risk_score(
            network=network,
            encryption_result=enc_analysis,
            config_findings=config_findings,
            rogue_findings=rogue_findings,
        )

        network["encryption_analysis"] = enc_analysis
        network["config_findings"] = config_findings
        network["rogue_findings"] = rogue_findings
        network["risk"] = risk
        network["signal_quality"] = signal_quality_label(network.get("signal", -100))
        analysed.append(network)

    ranked = rank_networks(analysed)
    console.print(f"[green]Analysis complete. Ranked {len(ranked)} networks.[/green]\n")
    logger.info(
        "Analysis completed",
        extra={"event": "analysis_completed", "network_count": len(ranked), "demo_mode": demo_mode},
    )
    return ranked, scan_meta


def save_to_history(networks: list[dict], scan_meta: dict) -> None:
    """Append this scan's summary to the bounded history file."""
    ensure_dir(OUTPUT_DIR)
    history = _load_history()

    entry = {
        "timestamp": scan_meta.get("timestamp"),
        "interface": scan_meta.get("interface"),
        "demo_mode": bool(scan_meta.get("demo_mode", False)),
        "networks": len(networks),
        "critical": sum(1 for item in networks if item.get("risk", {}).get("label") == "Critical"),
        "vulnerable": sum(1 for item in networks if item.get("risk", {}).get("label") == "Vulnerable"),
        "avg_score": (
            round(sum(item.get("risk", {}).get("score", 0) for item in networks) / len(networks), 1) if networks else 0
        ),
    }
    history.append(entry)
    history = history[-MAX_HISTORY_ENTRIES:]

    atomic_write_text(HISTORY_FILE, json.dumps(history, indent=2, ensure_ascii=False))
    logger.info("History updated", extra={"event": "history_updated", "entries": len(history)})


def show_history() -> None:
    """Print the scan history table to the console."""
    history = _load_history()
    if not history:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title="Scan History", show_lines=True, header_style="bold cyan", box=box.ASCII)
    table.add_column("Timestamp", min_width=20)
    table.add_column("Interface", width=12)
    table.add_column("Mode", width=7)
    table.add_column("Networks", justify="right", width=9)
    table.add_column("Critical", justify="right", width=9)
    table.add_column("Vulnerable", justify="right", width=10)
    table.add_column("Avg Score", justify="right", width=9)

    for entry in history[-20:]:
        critical = int(entry.get("critical", 0))
        critical_cell = f"[bright_red]{critical}[/bright_red]" if critical else str(critical)
        table.add_row(
            escape(safe_console_text(entry.get("timestamp", ""))),
            escape(safe_console_text(entry.get("interface", ""))),
            "demo" if entry.get("demo_mode") else "live",
            str(entry.get("networks", 0)),
            critical_cell,
            str(entry.get("vulnerable", 0)),
            str(entry.get("avg_score", 0)),
        )

    console.print(table)


def compare_scans(path_a: str, path_b: str) -> None:
    """Print a comparison between two JSON scan reports."""
    try:
        report_a = _load_report(path_a)
        report_b = _load_report(path_b)
    except (InputValidationError, json.JSONDecodeError) as exc:
        console.print(f"[red]Failed to load reports: {escape(safe_console_text(exc))}[/red]")
        return

    ts_a = report_a.get("report_metadata", {}).get("scan_started", path_a)
    ts_b = report_b.get("report_metadata", {}).get("scan_started", path_b)
    networks_a = _network_map(report_a)
    networks_b = _network_map(report_b)

    new_bssids = set(networks_b) - set(networks_a)
    gone_bssids = set(networks_a) - set(networks_b)
    common = set(networks_a) & set(networks_b)

    table = Table(
        title=f"Scan Comparison\n{safe_console_text(ts_a)} vs {safe_console_text(ts_b)}",
        show_lines=True,
        box=box.ASCII,
    )
    table.add_column("SSID")
    table.add_column("BSSID")
    table.add_column("Change")
    table.add_column("Score A -> B")

    for bssid in sorted(new_bssids):
        network = networks_b[bssid]
        table.add_row(
            escape(safe_console_text(network.get("ssid", ""))),
            escape(safe_console_text(bssid)),
            "[bright_green]NEW[/bright_green]",
            f"- -> {network.get('risk', {}).get('score', '?')}",
        )
    for bssid in sorted(gone_bssids):
        network = networks_a[bssid]
        table.add_row(
            escape(safe_console_text(network.get("ssid", ""))),
            escape(safe_console_text(bssid)),
            "[dim]GONE[/dim]",
            f"{network.get('risk', {}).get('score', '?')} -> -",
        )
    for bssid in sorted(common):
        score_a = _score(networks_a[bssid])
        score_b = _score(networks_b[bssid])
        delta = score_b - score_a
        colour = "bright_red" if delta > 5 else "bright_green" if delta < -5 else "white"
        table.add_row(
            escape(safe_console_text(networks_b[bssid].get("ssid", ""))),
            escape(safe_console_text(bssid)),
            f"[{colour}]{'+' if delta >= 0 else ''}{delta}[/{colour}]",
            f"{score_a} -> {score_b}",
        )

    console.print(table)


def main() -> int:
    """Application entry point."""
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(log_dir=LOG_DIR, level=logging.DEBUG if args.debug else logging.INFO)

    try:
        console.print(BANNER, style="cyan", highlight=False)
        console.print(Panel(ETHICS_DISCLAIMER.strip(), border_style="yellow", box=box.ASCII))

        if args.history:
            show_history()
            return 0

        if args.compare:
            compare_scans(args.compare[0], args.compare[1])
            return 0

        if not args.scan:
            parser.print_help()
            return 0

        networks, scan_meta = run_analysis(args.interface, args.duration, demo_mode=args.demo)
        if not networks:
            return 1

        save_to_history(networks, scan_meta)

        output = args.output.lower()
        if output in ("cli", "all"):
            render_report(networks, scan_meta, verbose=args.verbose)

        if output in ("json", "all"):
            json_path = save_json_report(networks, scan_meta)
            console.print(f"[green]OK JSON report saved -> [bold]{escape(json_path)}[/bold][/green]")

        if output in ("pdf", "all"):
            if not REPORTLAB_AVAILABLE:
                console.print("[red]ReportLab is not installed. Install with: pip install reportlab[/red]")
            else:
                pdf_path = save_pdf_report(networks, scan_meta)
                if pdf_path:
                    console.print(f"[green]OK PDF report saved -> [bold]{escape(pdf_path)}[/bold][/green]")

        return 0
    except KeyboardInterrupt:
        logger.warning("Interrupted by user", extra={"event": "interrupted"})
        console.print("[yellow]Interrupted.[/yellow]")
        return 130
    except InputValidationError as exc:
        logger.warning("Input validation failed", extra={"event": "validation_failed", "error": str(exc)})
        console.print(f"[red]{escape(str(exc))}[/red]")
        return 2
    except Exception as exc:
        logger.exception("Fatal application error", extra={"event": "fatal_error"})
        console.print(f"[red]Fatal error: {escape(safe_console_text(exc))}[/red]")
        return 1


def _interface_arg(value: str) -> str:
    try:
        return validate_interface_name(value)
    except InputValidationError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _duration_arg(value: str) -> int:
    try:
        return validate_timeout(int(value), max_seconds=MAX_SCAN_TIMEOUT)
    except (ValueError, InputValidationError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _load_history() -> list[dict]:
    path = Path(HISTORY_FILE)
    if not path.exists():
        return []
    try:
        data = load_json_file(path)
    except (InputValidationError, json.JSONDecodeError, OSError) as exc:
        logger.warning("History read failed", extra={"event": "history_read_failed", "error": str(exc)})
        return []
    return data if isinstance(data, list) else []


def _load_report(path: str) -> dict:
    data = load_json_file(path)
    if not isinstance(data, dict):
        raise InputValidationError("Report JSON must contain an object.")
    if not isinstance(data.get("networks", []), list):
        raise InputValidationError("Report JSON has an invalid networks field.")
    return data


def _network_map(report: dict) -> dict[str, dict]:
    networks: dict[str, dict] = {}
    for item in report.get("networks", []):
        if isinstance(item, dict):
            bssid = str(item.get("bssid", "")).upper()
            if bssid:
                networks[bssid] = item
    return networks


def _score(network: dict) -> int:
    try:
        return int(network.get("risk", {}).get("score", 0))
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":
    sys.exit(main())
