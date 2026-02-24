import argparse
import datetime
try:
    import config as _config
except Exception:
    from . import config as _config
from parser.unified_parser import UnifiedParser
from Analytics.frequency import FrequencyAnalyzer
from Analytics.detection import SecurityDetector
from Analytics.alerts import AlertEngine
from monitor import monitor
try:
    # pretty console UI for alerts and summaries
    from Analytics.ui import render_alert, render_dashboard
except Exception:
    render_alert = None
    render_dashboard = None


def analysis_mode(path, alerts_out: str | None = None):
    up = UnifiedParser(path)
    events = up.parse()

    fa = FrequencyAnalyzer(events)
    print("\nFrequency: top IPs")
    for ip, count in fa.top_ips(5):
        print(f" - {ip}: {count}")

    sd = SecurityDetector(events)
    ae = AlertEngine(sd)
    ae.generate_bruteforce_alerts(threshold=3)
    ae.generate_suspicious_user_alerts(threshold=3)
    alerts = ae.get_alerts()
    if alerts:
        print("\nAlerts:")
        if render_alert:
            # Pretty Rich-based rendering for each alert
            for a in alerts:
                render_alert(a, pretty=True)
        else:
            for a in alerts:
                print(a)

        # Optional dashboard by severity if available
        if render_dashboard:
            summary = {}
            for a in alerts:
                sev = a.get("severity", "UNKNOWN")
                summary[sev] = summary.get(sev, 0) + 1
            print()
            render_dashboard(summary, pretty=True)

        # Persist alerts to JSON so they are exportable
        if alerts_out:
            try:
                ae.to_json_file(alerts_out)
                print(f"\nSaved {len(alerts)} alerts to {alerts_out}")
            except Exception as e:
                print(f"\nFailed to save alerts to JSON: {e}")
    else:
        print("No alerts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analyzer CLI")
    parser.add_argument("--file", help="Analyze file once")
    parser.add_argument("--monitor", help="Monitor file live")
    parser.add_argument("--window", type=int, default=60, help="Time-window seconds for live mode")
    parser.add_argument("--threshold", type=int, default=3, help="Attempts threshold for time-window alerts")
    parser.add_argument(
        "--alerts-json",
        help="Path to write alerts JSON (batch or live). Defaults to a per-user alerts.json under the app config directory if not provided in batch mode.",
    )
    parser.add_argument("--show-frequency", action="store_true", help="Show frequency alerts in live monitor")
    # SMTP / email options (can be set via env or CLI)
    parser.add_argument("--smtp-host", help="SMTP host for email notifier")
    parser.add_argument("--smtp-port", help="SMTP port", type=int)
    parser.add_argument("--smtp-user", help="SMTP username")
    parser.add_argument("--smtp-pass", help="SMTP password (not persisted; use keyring-backed config for storage)")
    parser.add_argument("--email-from", help="From address for alerts")
    parser.add_argument("--email-to", help="Comma-separated recipient addresses")
    parser.add_argument("--email-test", action="store_true", help="Send a single test email using provided or saved SMTP config")
    parser.add_argument("--prompt-pass", action="store_true", help="Prompt for SMTP password at runtime instead of using CLI or saved config")
    args = parser.parse_args()

    if args.file:
        # Determine where to write alerts JSON for batch mode
        alerts_out = args.alerts_json or _config.alerts_path()
        analysis_mode(args.file, alerts_out=alerts_out)
    elif args.monitor:
        smtp_cfg = None
        if args.smtp_host or args.smtp_port or args.smtp_user or args.smtp_pass or args.email_from or args.email_to:
            smtp_cfg = {
                'host': args.smtp_host,
                'port': args.smtp_port,
                'user': args.smtp_user,
                'password': args.smtp_pass,
                'from_addr': args.email_from,
                'to_addrs': args.email_to
            }

        monitor(
            args.monitor,
            time_window_seconds=args.window,
            time_window_threshold=args.threshold,
            show_frequency=args.show_frequency,
            smtp_config=smtp_cfg,
            alerts_json=args.alerts_json,
        )
    elif args.email_test:
        # build SMTP config from CLI args overriding saved config
        saved = _config.load_config() or {}
        saved_smtp = saved.get('smtp') or {}

        host = args.smtp_host or saved_smtp.get('host')
        port = args.smtp_port or saved_smtp.get('port')
        user = args.smtp_user or saved_smtp.get('user')

        # Resolve password in order of precedence:
        # 1) explicit CLI flag
        # 2) keyring (if available)
        # 3) legacy plaintext field from config (if still present)
        password = args.smtp_pass or None
        if not password and hasattr(_config, "load_smtp_password"):
            password = _config.load_smtp_password(user, host)
        if not password:
            password = saved_smtp.get('password')

        # prompt for password at runtime if requested and not resolved yet
        if args.prompt_pass and not password:
            try:
                import getpass
                password = getpass.getpass(prompt='SMTP password: ')
            except Exception:
                password = None

        smtp_cfg = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'from_addr': args.email_from or saved_smtp.get('from_addr'),
            'to_addrs': args.email_to or saved_smtp.get('to_addrs')
        }

        # validate
        if not smtp_cfg.get('host'):
            print("No SMTP host configured. Provide via CLI (--smtp-host) or register with the dashboard.")
        elif not smtp_cfg.get('to_addrs'):
            print("No recipient address configured. Provide --email-to or register via dashboard.")
        else:
            from notifiers.email import email_notifier
            alert = {
                'alert_type': 'TestEmail',
                'severity': 'LOW',
                'evidence': {'test': 'email-test'},
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            print("Sending test email (dry_run=False)...")
            ok = email_notifier(alert, smtp_config=smtp_cfg, dry_run=False)
            if ok is True:
                print("Test email sent successfully.")
            else:
                print("Test email failed. See output above for details.")
    else:
        parser.print_help()
