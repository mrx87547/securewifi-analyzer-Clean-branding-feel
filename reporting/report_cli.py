"""
Rich terminal reporting for WiFi Security Analyzer.
"""

from __future__ import annotations

import logging
from datetime import datetime

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from utils.helpers import safe_console_text

logger = logging.getLogger(__name__)
console = Console(safe_box=True, emoji=False)

RISK_COLOUR: dict[str, str] = {
    "Secure": "bright_green",
    "Moderate": "yellow",
    "Vulnerable": "orange3",
    "Critical": "bright_red",
    "Low": "bright_green",
    "Medium": "yellow",
    "High": "orange3",
}

ENC_COLOUR: dict[str, str] = {
    "WPA3": "bright_green",
    "WPA2": "yellow",
    "WPA": "orange3",
    "WEP": "bright_red",
    "OPEN": "bright_red",
    "UNKNOWN": "dim",
}


def render_report(networks: list[dict], scan_meta: dict, verbose: bool = False) -> None:
    """Render the complete CLI report."""
    _render_scan_summary(scan_meta, networks)
    _render_network_table(networks)
    if verbose:
        _render_detailed_panels(networks)
    _render_most_vulnerable(networks)


def _render_scan_summary(meta: dict, networks: list[dict]) -> None:
    ts = meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    iface = meta.get("interface", "unknown")
    total = len(networks)
    critical = sum(1 for item in networks if item.get("risk", {}).get("label") == "Critical")
    vulnerable = sum(1 for item in networks if item.get("risk", {}).get("label") == "Vulnerable")
    secure = sum(1 for item in networks if item.get("risk", {}).get("label") == "Secure")

    summary = (
        f"[bold]Interface:[/bold]  {_m(iface)}\n"
        f"[bold]Mode:[/bold]       {'demo' if meta.get('demo_mode') else 'live'}\n"
        f"[bold]Scan time:[/bold]  {_m(ts)}\n"
        f"[bold]Networks:[/bold]   {total} found\n"
        f"[bold]Critical:[/bold]   [bright_red]{critical}[/bright_red]   "
        f"[bold]Vulnerable:[/bold] [orange3]{vulnerable}[/orange3]   "
        f"[bold]Secure:[/bold]     [bright_green]{secure}[/bright_green]"
    )
    console.print(Panel(summary, title="[bold cyan]Scan Summary[/bold cyan]", box=box.ASCII))


def _render_network_table(networks: list[dict]) -> None:
    table = Table(
        title="[bold]Wireless Networks Detected[/bold]",
        box=box.ASCII,
        show_lines=True,
        header_style="bold cyan",
    )

    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("SSID", style="white", min_width=18)
    table.add_column("BSSID", style="dim", width=17)
    table.add_column("Signal", width=9, justify="right")
    table.add_column("Ch", width=4, justify="right")
    table.add_column("Encryption", width=10)
    table.add_column("WPS", width=5, justify="center")
    table.add_column("Score", width=7, justify="center")
    table.add_column("Risk", width=11, justify="center")

    for idx, network in enumerate(networks, start=1):
        risk = network.get("risk", {})
        score = risk.get("score", 0)
        label = risk.get("label", "Unknown")
        encryption = network.get("encryption", "UNKNOWN")
        signal = network.get("signal", -100)
        ssid = network.get("ssid", "<hidden>")
        wps = "yes" if network.get("wps") else "no"

        risk_colour = RISK_COLOUR.get(label, "white")
        enc_colour = ENC_COLOUR.get(encryption, "white")
        signal_colour = "bright_green" if signal >= -60 else "yellow" if signal >= -75 else "red"
        ssid_markup = f"[dim]{_m(ssid)}[/dim]" if ssid == "<hidden>" else f"[bold]{_m(ssid)}[/bold]"

        table.add_row(
            str(idx),
            ssid_markup,
            _m(network.get("bssid", "")),
            f"[{signal_colour}]{signal} dBm[/{signal_colour}]",
            str(network.get("channel", "?")),
            f"[{enc_colour}]{_m(encryption)}[/{enc_colour}]",
            f"[orange3]{wps}[/orange3]" if network.get("wps") else f"[dim]{wps}[/dim]",
            f"[{risk_colour}]{score}[/{risk_colour}]",
            f"[{risk_colour}][bold]{_m(label)}[/bold][/{risk_colour}]",
        )

    console.print(table)


def _render_detailed_panels(networks: list[dict]) -> None:
    console.print(Rule("[bold]Detailed Findings[/bold]", style="cyan"))
    for network in networks:
        _render_single_network_panel(network)


def _render_single_network_panel(network: dict) -> None:
    risk = network.get("risk", {})
    label = risk.get("label", "Unknown")
    score = risk.get("score", 0)
    colour = RISK_COLOUR.get(label, "white")

    header = (
        f"[bold white]{_m(network.get('ssid', '<hidden>'))}[/bold white]  "
        f"[dim]{_m(network.get('bssid', ''))}[/dim]  "
        f"Risk: [{colour}]{_m(label)} ({score}/100)[/{colour}]"
    )

    lines: list[str] = []
    enc_result = network.get("encryption_analysis", {})
    if enc_result:
        lines.extend(_finding_lines(enc_result, enc_result.get("vulnerability", "")))
        if enc_result.get("wps_warning"):
            lines.append(f"  [orange3]WPS: {_m(enc_result['wps_warning'], limit=1200)}[/orange3]")

    for finding in network.get("config_findings", []):
        lines.append("")
        lines.extend(_finding_lines(finding, finding.get("check", "")))

    for finding in network.get("rogue_findings", []):
        lines.append("")
        lines.extend(_finding_lines(finding, finding.get("check", "")))

    body = "\n".join(lines) if lines else "[dim]No findings.[/dim]"
    console.print(Panel(body, title=header, border_style=colour, box=box.ASCII))
    console.print()


def _finding_lines(finding: dict, title: object) -> list[str]:
    level = finding.get("risk_level", "")
    colour = RISK_COLOUR.get(level, "white")
    return [
        f"[{colour}]* {_m(title)} [{_m(level)}][/{colour}]",
        f"  {_m(finding.get('description', ''), limit=1500)}",
        f"  [bold yellow]Scenario:[/bold yellow] {_m(finding.get('unauthorized_access_scenario', ''), limit=2000)}",
        f"  [bold green]Fix:[/bold green] {_m(finding.get('recommendation', ''), limit=1500)}",
    ]


def _render_most_vulnerable(networks: list[dict]) -> None:
    if not networks:
        return

    worst = networks[0]
    risk = worst.get("risk", {})
    label = risk.get("label", "Unknown")
    score = risk.get("score", 0)
    colour = RISK_COLOUR.get(label, "white")

    text = (
        "[bold]Most Vulnerable Network:[/bold]  "
        f"[bold white]{_m(worst.get('ssid', '<hidden>'))}[/bold white]  "
        f"[{colour}]Score: {score} -> {_m(label)}[/{colour}]\n"
        f"[bold]Top Risk:[/bold]  {_m(risk.get('top_risk', 'N/A'))}"
    )
    console.print(Panel(text, title="[bold red]High-Priority Alert[/bold red]", border_style="red", box=box.ASCII))


def _m(value: object, *, limit: int = 500) -> str:
    return escape(safe_console_text(value, limit=limit))
