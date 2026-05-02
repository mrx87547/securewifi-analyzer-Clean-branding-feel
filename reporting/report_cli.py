"""
reporting/report_cli.py
Renders scan results to the terminal using the Rich library.
Produces colour-coded tables, per-network detail panels, and a summary.
"""

import logging
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.columns import Columns
from rich.padding import Padding

logger = logging.getLogger(__name__)
console = Console()


# ── Risk colour mapping ───────────────────────────────────────────────────────
RISK_COLOUR: dict[str, str] = {
    "Secure":     "bright_green",
    "Moderate":   "yellow",
    "Vulnerable": "orange3",
    "Critical":   "bright_red",
    "Low":        "bright_green",
    "Medium":     "yellow",
    "High":       "orange3",
}

ENC_COLOUR: dict[str, str] = {
    "WPA3":    "bright_green",
    "WPA2":    "yellow",
    "WPA":     "orange3",
    "WEP":     "bright_red",
    "OPEN":    "bright_red",
    "UNKNOWN": "dim",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def render_report(
    networks:  list[dict],
    scan_meta: dict,
    verbose:   bool = False,
) -> None:
    """Render the complete CLI report.

    Args:
        networks:  List of fully-analysed network dicts.
        scan_meta: Metadata dict (interface, timestamp, etc.).
        verbose:   If True, print detailed per-network vulnerability panels.
    """
    _render_scan_summary(scan_meta, networks)
    _render_network_table(networks)
    if verbose:
        _render_detailed_panels(networks)
    _render_most_vulnerable(networks)


# ── Sections ──────────────────────────────────────────────────────────────────

def _render_scan_summary(meta: dict, networks: list[dict]) -> None:
    """Print a compact scan metadata panel.

    Args:
        meta:     Scan metadata dict.
        networks: Analysed networks list.
    """
    ts        = meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    iface     = meta.get("interface", "unknown")
    total     = len(networks)
    critical  = sum(1 for n in networks if n.get("risk", {}).get("label") == "Critical")
    vulnerable= sum(1 for n in networks if n.get("risk", {}).get("label") == "Vulnerable")
    secure    = sum(1 for n in networks if n.get("risk", {}).get("label") == "Secure")

    summary = (
        f"[bold]Interface:[/bold]  {iface}\n"
        f"[bold]Scan time:[/bold]  {ts}\n"
        f"[bold]Networks:[/bold]   {total} found\n"
        f"[bold]Critical:[/bold]   [bright_red]{critical}[/bright_red]   "
        f"[bold]Vulnerable:[/bold] [orange3]{vulnerable}[/orange3]   "
        f"[bold]Secure:[/bold]     [bright_green]{secure}[/bright_green]"
    )
    console.print(Panel(summary, title="[bold cyan]Scan Summary[/bold cyan]", box=box.ROUNDED))


def _render_network_table(networks: list[dict]) -> None:
    """Print the main network overview table.

    Args:
        networks: Analysed networks sorted by risk score.
    """
    table = Table(
        title="[bold]Wireless Networks Detected[/bold]",
        box=box.DOUBLE_EDGE,
        show_lines=True,
        header_style="bold cyan",
    )

    table.add_column("#",          style="dim",  width=3,  justify="right")
    table.add_column("SSID",       style="white", min_width=18)
    table.add_column("BSSID",      style="dim",   width=17)
    table.add_column("Signal",     width=9,  justify="right")
    table.add_column("Ch",         width=4,  justify="right")
    table.add_column("Encryption", width=10)
    table.add_column("WPS",        width=5,  justify="center")
    table.add_column("Score",      width=7,  justify="center")
    table.add_column("Risk",       width=11, justify="center")

    for idx, net in enumerate(networks, start=1):
        risk  = net.get("risk", {})
        score = risk.get("score", 0)
        label = risk.get("label", "Unknown")
        enc   = net.get("encryption", "UNKNOWN")
        rssi  = net.get("signal", -100)
        ssid  = net.get("ssid", "<hidden>")
        wps   = "✓" if net.get("wps") else "✗"

        risk_colour  = RISK_COLOUR.get(label, "white")
        enc_colour   = ENC_COLOUR.get(enc, "white")
        signal_colour = (
            "bright_green" if rssi >= -60
            else "yellow" if rssi >= -75
            else "red"
        )

        table.add_row(
            str(idx),
            f"[bold]{'[dim]' if ssid == '<hidden>' else ''}{ssid}[/bold]",
            net.get("bssid", ""),
            f"[{signal_colour}]{rssi} dBm[/{signal_colour}]",
            str(net.get("channel", "?")),
            f"[{enc_colour}]{enc}[/{enc_colour}]",
            f"[bright_green]{wps}[/bright_green]" if net.get("wps") else f"[dim]{wps}[/dim]",
            f"[{risk_colour}]{score}[/{risk_colour}]",
            f"[{risk_colour}][bold]{label}[/bold][/{risk_colour}]",
        )

    console.print(table)


def _render_detailed_panels(networks: list[dict]) -> None:
    """Print per-network vulnerability detail panels.

    Args:
        networks: Analysed networks list.
    """
    console.print(Rule("[bold]Detailed Findings[/bold]", style="cyan"))
    for net in networks:
        _render_single_network_panel(net)


def _render_single_network_panel(net: dict) -> None:
    """Render a detailed panel for one network.

    Args:
        net: Fully-analysed network dict.
    """
    risk  = net.get("risk", {})
    label = risk.get("label", "Unknown")
    score = risk.get("score", 0)
    colour = RISK_COLOUR.get(label, "white")

    header = (
        f"[bold white]{net.get('ssid', '<hidden>')}[/bold white]  "
        f"[dim]{net.get('bssid', '')}[/dim]  "
        f"  Risk: [{colour}]{label} ({score}/100)[/{colour}]"
    )

    lines: list[str] = []

    # Encryption finding
    enc_r = net.get("encryption_analysis", {})
    if enc_r:
        lvl = enc_r.get("risk_level", "")
        c   = RISK_COLOUR.get(lvl, "white")
        lines.append(f"[{c}]◆ {enc_r.get('vulnerability', '')} [{lvl}][/{c}]")
        lines.append(f"  {enc_r.get('description', '')}")
        lines.append(f"  [bold yellow]Scenario:[/bold yellow] {enc_r.get('unauthorized_access_scenario', '')}")
        lines.append(f"  [bold green]Fix:[/bold green] {enc_r.get('recommendation', '')}")
        if enc_r.get("wps_warning"):
            lines.append(f"  [orange3]⚠ WPS: {enc_r['wps_warning']}[/orange3]")

    # Config findings
    for cf in net.get("config_findings", []):
        lvl = cf.get("risk_level", "")
        c   = RISK_COLOUR.get(lvl, "white")
        lines.append("")
        lines.append(f"[{c}]◆ {cf.get('check', '')} [{lvl}][/{c}]")
        lines.append(f"  {cf.get('description', '')}")
        lines.append(f"  [bold yellow]Scenario:[/bold yellow] {cf.get('unauthorized_access_scenario', '')}")
        lines.append(f"  [bold green]Fix:[/bold green] {cf.get('recommendation', '')}")

    # Rogue AP findings
    for rf in net.get("rogue_findings", []):
        lvl = rf.get("risk_level", "")
        c   = RISK_COLOUR.get(lvl, "white")
        lines.append("")
        lines.append(f"[{c}]◆ {rf.get('check', '')} [{lvl}][/{c}]")
        lines.append(f"  {rf.get('description', '')}")
        lines.append(f"  [bold yellow]Scenario:[/bold yellow] {rf.get('unauthorized_access_scenario', '')}")
        lines.append(f"  [bold green]Fix:[/bold green] {rf.get('recommendation', '')}")

    body = "\n".join(lines) if lines else "[dim]No findings.[/dim]"
    console.print(
        Panel(body, title=header, border_style=colour, box=box.ROUNDED)
    )
    console.print()


def _render_most_vulnerable(networks: list[dict]) -> None:
    """Highlight the single most vulnerable network.

    Args:
        networks: Analysed networks sorted by risk score.
    """
    if not networks:
        return
    worst = networks[0]
    risk  = worst.get("risk", {})
    label = risk.get("label", "Unknown")
    score = risk.get("score", 0)
    colour = RISK_COLOUR.get(label, "white")

    text = (
        f"[bold]Most Vulnerable Network:[/bold]  "
        f"[bold white]{worst.get('ssid', '<hidden>')}[/bold white]  "
        f"  [{colour}]Score: {score} → {label}[/{colour}]\n"
        f"[bold]Top Risk:[/bold]  {risk.get('top_risk', 'N/A')}"
    )
    console.print(
        Panel(text, title="[bold red]⚠  High-Priority Alert[/bold red]", border_style="red", box=box.HEAVY)
    )
