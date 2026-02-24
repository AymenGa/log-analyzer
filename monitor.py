import time
from parser.detector import LogDetector
from Analytics.detection import SecurityDetector
from Analytics.alerts import AlertEngine
import os

try:
    from notifiers.email import email_notifier
except Exception:
    email_notifier = None


def tail_f(path):
    with open(path, "r", errors="ignore") as f:
        # go to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def build_unified(parsed):
    # parsed is parser.parse_line output (raw keys)
    if not parsed:
        return None
    return {
        "timestamp": parsed.get("timestamp"),
        "ip": parsed.get("ip"),
        "event_type": parsed.get("event" ) if parsed.get("event") else parsed.get("event_type"),
        "user": parsed.get("username") or parsed.get("user"),
        "method": parsed.get("method"),
        "url": parsed.get("path") or parsed.get("url"),
        "status": parsed.get("status"),
        "size": parsed.get("size"),
        "raw": parsed.get("raw")
    }


def monitor(path, time_window_threshold=3, time_window_seconds=60, freq_threshold=20, show_frequency=False, smtp_config=None, alerts_json: str | None = None):
    detector = LogDetector(path).detect()
    if detector is None:
        print("No parser detected for this file. Aborting monitor.")
        return

    sd = SecurityDetector([])
    ae = AlertEngine(sd)

    # optional JSON persistence for live alerts
    if alerts_json:
        ae.set_alerts_path(alerts_json)

    # configure email notifier: prefer CLI-provided smtp_config, else fall back to env vars
    cfg = None
    if smtp_config:
        cfg = smtp_config
    else:
        # build from environment if available
        host = os.getenv('SMTP_HOST')
        to = os.getenv('EMAIL_TO')
        if host or to:
            cfg = {
                'host': os.getenv('SMTP_HOST'),
                'port': int(os.getenv('SMTP_PORT')) if os.getenv('SMTP_PORT') else None,
                'user': os.getenv('SMTP_USER'),
                'password': os.getenv('SMTP_PASS'),
                'from_addr': os.getenv('EMAIL_FROM'),
                'to_addrs': os.getenv('EMAIL_TO')
            }

    if email_notifier is not None:
        # determine dry_run: true unless cfg provides both host and to_addrs
        dry_run = True
        if cfg and cfg.get('host') and cfg.get('to_addrs'):
            dry_run = False

        # if smtp_config doesn't include password and an env var is set, pick it up
        if cfg and not cfg.get('password') and os.getenv('SMTP_PASS'):
            cfg['password'] = os.getenv('SMTP_PASS')

        if cfg:
            ae.notifier = lambda alert: email_notifier(alert, smtp_config=cfg, dry_run=dry_run)
        else:
            ae.notifier = lambda alert: email_notifier(alert, dry_run=True)

    print(f"Monitoring {path} (time-window={time_window_seconds}s, threshold={time_window_threshold})")

    for line in tail_f(path):
        parsed = detector.parse_line(line)
        unified = build_unified(parsed)
        if unified is None:
            continue
        ae.process_event(unified, time_window_threshold=time_window_threshold, time_window_seconds=time_window_seconds, freq_threshold=freq_threshold, show_frequency=show_frequency)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python monitor.py /path/to/log")
    else:
        monitor(sys.argv[1])
