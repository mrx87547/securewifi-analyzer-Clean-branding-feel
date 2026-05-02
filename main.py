#!/usr/bin/env python3
"""
main.py
WiFi Security Analyzer — CLI entry point.

Usage:
    python main.py --scan --interface wlan0 --output cli
    python main.py --scan --interface wlan0 --output json
    python main.py --scan --interface wlan0 --output pdf --verbose
    python main.py --scan --output all --verbose
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich import box

# ── Local imports ──────────────────────────────────────────────────────────────
from config.settings import (
    BANNER, ETHICS_DISCLAIMER,
    TOOL_NAME, TOOL_VERSION,
    HISTORY_FILE, OUTPUT_DIR,
)
from utils.helpers import setup_logging, ensure_dir, timestamp_now, signal_quality_label
from scanner.scan import scan_networks
from analyzer.encryption import analyse_encryption
from analyzer.vulnerabilities import analyse_configuration
from analyzer.rogue import detect_rogue_aps
from risk_engine.scoring import calculate_risk_score, rank_networks
from reporting.report_cli import render_report
from reporting.report_json import save_json_report
from reporting.report_pdf import save_pdf_report, REPORTLAB_AVAILABLE

console = Console()
logger  = logging.getLogger(__name__)


# ── CLI Argument Parser ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="wsa",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Wireless Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan --interface wlan0 --output cli
  python main.py --scan --interface wlan0 --output json
  python main.py --scan --interface wlan0 --output pdf --verbose
  python main.py --scan --output all --verbose
  python main.py --history
        """,
    )

    parser.add_argument(
        "--scan", action="store_true",
        help="Perform a wireless network scan",
    )
    parser.add_argument(
        "--interface", "-i", default="wlan0", metavar="IFACE",
        help="Wireless interface to use (default: wlan0)",
    )
    parser.add_argument(
        "--output", "-o", default="cli",
        choices=["cli", "json", "pdf", "all"],
        help="Output format: cli | json | pdf | all (default: cli)",
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=15, metavar="SECS",
        help="Scan duration in seconds (default: 15)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed per-network vulnerability panels in CLI output",
    )
    parser.add_argument(
        "--history", action="store_true",
        help="Show a summary of previous scan history",
    )
    parser.add_argument(
        "--compare", nargs=2, metavar=("SCAN_A", "SCAN_B"),
        help="Compare two JSON scan reports (file paths)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug-level logging",
    )
    return parser


# ── Core Pipeline ──────────────────────────────────────────────────────────────

def run_analysis(interface: str, duration: int) -> tuple[list[dict], dict]:
    """Execute the full scan and analysis pipeline.

    Args:
        interface: Wireless interface name.
        duration:  Scan timeout in seconds.

    Returns:
        Tuple of (ranked analysed networks, scan metadata dict).
    """
    scan_meta = {
        "interface": interface,
        "timestamp": timestamp_now(),
        "duration":  duration,
    }

    # ── Step 1: Scan ──────────────────────────────────────────────────────────
    console.print(f"[cyan]  Scanning on [bold]{interface}[/bold] …[/cyan]")
    raw_networks = scan_networks(interface=interface, timeout=duration)

    if not raw_networks:
        console.print("[red]No networks found.  Check interface and permissions.[/red]")
        return [], scan_meta

    console.print(f"[green]  Found {len(raw_networks)} network(s).[/green]")

    # ── Step 2: Rogue AP detection (needs full set) ───────────────────────────
    console.print("[cyan]  Detecting rogue APs …[/cyan]")
    rogue_map = detect_rogue_aps(raw_networks)   # BSSID → list[finding]

    # ── Step 3: Per-network analysis ──────────────────────────────────────────
    console.print("[cyan]  Analysing security configurations …[/cyan]")
    analysed: list[dict] = []

    for net in raw_networks:
        enc_analysis    = analyse_encryption(net)
        config_findings = analyse_configuration(net)
        rogue_findings  = rogue_map.get(net["bssid"], [])

        risk = calculate_risk_score(
            network=net,
            encryption_result=enc_analysis,
            config_findings=config_findings,
            rogue_findings=rogue_findings,
        )

        net["encryption_analysis"] = enc_analysis
        net["config_findings"]     = config_findings
        net["rogue_findings"]      = rogue_findings
        net["risk"]                = risk
        net["signal_quality"]      = signal_quality_label(net.get("signal", -100))
        analysed.append(net)

    ranked = rank_networks(analysed)
    console.print(f"[green]  Analysis complete.  Ranked {len(ranked)} networks.[/green]\n")
    return ranked, scan_meta


# ── History ───────────────────────────────────────────────────────────────────

def save_to_history(networks: list[dict], scan_meta: dict) -> None:
    """Append this scan's summary to the history file.

    Args:
        networks:  Analysed networks.
        scan_meta: Scan metadata.
    """
    ensure_dir(OUTPUT_DIR)
    history: list[dict] = []

    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
                history = json.load(fh)
        except (json.JSONDecodeError, OSError):
            history = []

    entry = {
        "timestamp":  scan_meta.get("timestamp"),
        "interface":  scan_meta.get("interface"),
        "networks":   len(networks),
        "critical":   sum(1 for n in networks if n.get("risk", {}).get("label") == "Critical"),
        "vulnerable": sum(1 for n in networks if n.get("risk", {}).get("label") == "Vulnerable"),
        "avg_score":  (
            round(sum(n.get("risk", {}).get("score", 0) for n in networks) / len(networks), 1)
            if networks else 0
        ),
    }
    history.append(entry)

    with open(HISTORY_FILE, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2)


def show_history() -> None:
    """Print the scan history table to the console."""
    if not os.path.exists(HISTORY_FILE):
        console.print("[yellow]No scan history found.[/yellow]")
        return

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
            history = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Failed to read history: {exc}[/red]")
        return

    from rich.table import Table
    tbl = Table(title="Scan History", show_lines=True, header_style="bold cyan")
    tbl.add_column("Timestamp",  min_width=20)
    tbl.add_column("Interface",  width=10)
    tbl.add_column("Networks",   justify="right", width=9)
    tbl.add_column("Critical",   justify="right", width=9)
    tbl.add_column("Vulnerable", justify="right", width=10)
    tbl.add_column("Avg Score",  justify="right", width=9)

    for entry in history[-20:]:    # Show latest 20
        crit_str = str(entry.get("critical", 0))
        crit_coloured = (
            f"[bright_red]{crit_str}[/bright_red]"
            if int(crit_str) > 0 else crit_str
        )
        tbl.add_row(
            entry.get("timestamp", ""),
            entry.get("interface", ""),
            str(entry.get("networks", 0)),
            crit_coloured,
            str(entry.get("vulnerable", 0)),
            str(entry.get("avg_score", 0)),
        )

    console.print(tbl)


# ── Scan Comparison ───────────────────────────────────────────────────────────

def compare_scans(path_a: str, path_b: str) -> None:
    """Print a comparison between two JSON scan reports.

    Args:
        path_a: Path to the first JSON report.
        path_b: Path to the second JSON report.
    """
    def _load(p: str) -> dict:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    try:
        a, b = _load(path_a), _load(path_b)
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Failed to load reports: {exc}[/red]")
        return

    ts_a = a.get("report_metadata", {}).get("scan_started", path_a)
    ts_b = b.get("report_metadata", {}).get("scan_started", path_b)

    nets_a = {n["bssid"]: n for n in a.get("networks", [])}
    nets_b = {n["bssid"]: n for n in b.get("networks", [])}

    new_bssids  = set(nets_b) - set(nets_a)
    gone_bssids = set(nets_a) - set(nets_b)
    common      = set(nets_a) & set(nets_b)

    from rich.table import Table
    tbl = Table(title=f"Scan Comparison\n{ts_a}  vs  {ts_b}", show_lines=True)
    tbl.add_column("SSID")
    tbl.add_column("BSSID")
    tbl.add_column("Change")
    tbl.add_column("Score A → B")

    for bssid in sorted(new_bssids):
        n = nets_b[bssid]
        tbl.add_row(
            n.get("ssid", ""), bssid,
            "[bright_green]NEW[/bright_green]",
            f"—  →  {n.get('risk', {}).get('score', '?')}",
        )
    for bssid in sorted(gone_bssids):
        n = nets_a[bssid]
        tbl.add_row(
            n.get("ssid", ""), bssid,
            "[dim]GONE[/dim]",
            f"{n.get('risk', {}).get('score', '?')}  →  —",
        )
    for bssid in sorted(common):
        sa = nets_a[bssid].get("risk", {}).get("score", 0)
        sb = nets_b[bssid].get("risk", {}).get("score", 0)
        delta = sb - sa
        colour = "bright_red" if delta > 5 else "bright_green" if delta < -5 else "white"
        tbl.add_row(
            nets_b[bssid].get("ssid", ""), bssid,
            f"[{colour}]{'+' if delta >= 0 else ''}{delta}[/{colour}]",
            f"{sa}  →  {sb}",
        )

    console.print(tbl)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    """Application entry point.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = build_parser()
    args   = parser.parse_args()

    # Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(level=log_level)

    # Banner + disclaimer
    console.print(BANNER, style="cyan", highlight=False)
    console.print(Panel(
        ETHICS_DISCLAIMER.strip(),
        border_style="yellow",
        box=box.HEAVY,
    ))

    # ── History ───────────────────────────────────────────────────────────────
    if args.history:
        show_history()
        return 0

    # ── Compare ───────────────────────────────────────────────────────────────
    if args.compare:
        compare_scans(args.compare[0], args.compare[1])
        return 0

    # ── Scan + Analyse ────────────────────────────────────────────────────────
    if not args.scan:
        parser.print_help()
        return 0

    networks, scan_meta = run_analysis(args.interface, args.duration)

    if not networks:
        return 1

    # Save to history
    save_to_history(networks, scan_meta)

    # ── Output ────────────────────────────────────────────────────────────────
    output = args.output.lower()

    if output in ("cli", "all"):
        render_report(networks, scan_meta, verbose=args.verbose)

    if output in ("json", "all"):
        json_path = save_json_report(networks, scan_meta)
        console.print(f"[green]✓ JSON report saved → [bold]{json_path}[/bold][/green]")

    if output in ("pdf", "all"):
        if not REPORTLAB_AVAILABLE:
            console.print(
                "[red]ReportLab is not installed.  "
                "Install with: pip install reportlab[/red]"
            )
        else:
            pdf_path = save_pdf_report(networks, scan_meta)
            if pdf_path:
                console.print(f"[green]✓ PDF report saved → [bold]{pdf_path}[/bold][/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
