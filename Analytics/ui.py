try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False


def render_alert(alert, pretty=True):
    """Render a single alert to the console. Falls back to simple print if Rich isn't available."""
    if pretty and RICH_AVAILABLE:
        sev = alert.get("severity", "UNKNOWN")
        score = alert.get("risk_score")
        atype = alert.get("alert_type")
        ts = alert.get("timestamp")

        header = Text(f" {atype} ")
        if sev == "HIGH":
            header.stylize("bold white on red")
        elif sev == "MEDIUM":
            header.stylize("bold white on orange3")
        else:
            header.stylize("bold black on green")

        body = Table.grid(expand=True)
        body.add_column(ratio=2)
        body.add_column(ratio=3)

        idn = alert.get("source_ip") or alert.get("user") or "-"
        body.add_row("ID:", str(idn))
        body.add_row("Severity:", sev)
        if score is not None:
            body.add_row("Risk Score:", str(score))

        ev = alert.get("evidence", {})
        for k, v in ev.items():
            body.add_row(k, str(v))

        body.add_row("Timestamp:", ts or "-")

        panel = Panel(body, title=header, expand=False, padding=(1, 2))
        console.print(panel)
    else:
        # fallback
        atype = alert.get("alert_type")
        sev = alert.get("severity")
        idn = alert.get("source_ip") or alert.get("user") or "-"
        ev = alert.get("evidence", {})
        score = alert.get("risk_score")
        parts = [f"[{sev}] {atype} id={idn}"]
        if score is not None:
            parts.append(f"score={score}")
        for k, v in ev.items():
            parts.append(f"{k}={v}")
        if alert.get("timestamp"):
            parts.append(alert.get("timestamp"))
        print(" | ".join(parts))


def render_dashboard(summary, pretty=True):
    """Render a small dashboard summary: counts by severity."""
    if pretty and RICH_AVAILABLE:
        table = Table(title="Alert Summary", show_lines=False)
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev, cnt in summary.items():
            table.add_row(sev, str(cnt))
        console.print(table)
    else:
        print("ALERT SUMMARY:")
        for sev, cnt in summary.items():
            print(f"{sev}: {cnt}")
