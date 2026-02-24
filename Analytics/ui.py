try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False

from typing import Dict
try:
    from .. import config as _config
except Exception:
    # when run as script from project root
    import config as _config


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
    # Offer to register email if none configured
    try:
        cfg = _config.load_config()
    except Exception:
        cfg = {}

    if not cfg.get('smtp'):
        try:
            resp = input("No email configured for alerts. Register now? (y/N): ").strip().lower()
        except Exception:
            resp = 'n'
        if resp == 'y':
            host = input("SMTP host (e.g. smtp.gmail.com): ").strip()
            port = input("SMTP port (e.g. 587): ").strip()
            user = input("SMTP username (leave blank for none): ").strip()
            password = input("SMTP password (will be saved in config): ").strip()
            from_addr = input("From address (alerts from): ").strip()
            to_addrs = input("Recipient addresses (comma-separated): ").strip()
            smtp = {
                'host': host or None,
                'port': int(port) if port else None,
                'user': user or None,
                'password': password or None,
                'from_addr': from_addr or None,
                'to_addrs': to_addrs
            }
            cfg['smtp'] = smtp
            try:
                _config.save_config(cfg)
                print("Saved email configuration to:", _config.config_path())
            except Exception as e:
                print("Failed to save config:", e)
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
