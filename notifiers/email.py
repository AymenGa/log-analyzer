import os
import smtplib
from email.message import EmailMessage
import json
import time
import logging

try:
    from rich.console import Console

    _RICH_AVAILABLE = True
    _console = Console()
except Exception:
    _RICH_AVAILABLE = False
    _console = None


logger = logging.getLogger("log_analyzer.email")
if not logger.handlers:
    handler = logging.StreamHandler()
    # Human-readable but still structured-ish: time level component and key=value details.
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [email_notifier] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def email_notifier(alert, smtp_config=None, dry_run=True, timeout=10, max_retries=3, backoff_seconds=2):
    """Send alert via SMTP email.

    smtp_config: dict with keys host, port, user, password, from_addr, to_addrs (list)
    If dry_run=True or smtp_config missing, print the email content instead of sending.
    """
    cfg = smtp_config or {
        'host': os.getenv('SMTP_HOST'),
        'port': int(os.getenv('SMTP_PORT') or 0) if os.getenv('SMTP_PORT') else None,
        'user': os.getenv('SMTP_USER'),
        'password': os.getenv('SMTP_PASS'),
        'from_addr': os.getenv('EMAIL_FROM'),
        'to_addrs': os.getenv('EMAIL_TO')
    }

    # normalize to_addrs list
    to_addrs = cfg.get('to_addrs')
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.split(',') if a.strip()]

    subject = f"[{alert.get('severity','UNKNOWN')}] {alert.get('alert_type')} - {alert.get('source_ip') or alert.get('user','') }"

    ev = alert.get('evidence', {})

    # Plain-text summary
    summary_lines = []
    summary_lines.append(f"Alert: {alert.get('alert_type')}")
    summary_lines.append(f"Severity: {alert.get('severity')}")
    if 'risk_score' in alert:
        summary_lines.append(f"Risk score: {alert['risk_score']}")
    if ev:
        for k, v in ev.items():
            summary_lines.append(f"{k}: {v}")
    if alert.get('timestamp'):
        summary_lines.append(f"Timestamp: {alert.get('timestamp')}")

    plain_body = "\n".join(summary_lines)

    # HTML-friendly body
    html_rows = []
    html_rows.append(f"<tr><th align=left>Alert</th><td>{alert.get('alert_type')}</td></tr>")
    html_rows.append(f"<tr><th align=left>Severity</th><td>{alert.get('severity')}</td></tr>")
    if 'risk_score' in alert:
        html_rows.append(f"<tr><th align=left>Risk score</th><td>{alert['risk_score']}</td></tr>")
    for k, v in ev.items():
        html_rows.append(f"<tr><th align=left>{k}</th><td>{v}</td></tr>")
    if alert.get('timestamp'):
        html_rows.append(f"<tr><th align=left>Timestamp</th><td>{alert.get('timestamp')}</td></tr>")

    html_body = f"""
    <html>
      <body>
        <h2>Alert: {alert.get('alert_type')}</h2>
        <table border="0" cellpadding="4">
          {''.join(html_rows)}
        </table>
        <p>Full alert JSON is attached.</p>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = cfg.get('from_addr') or 'alerts@example.com'
    msg['To'] = ', '.join(to_addrs or [])
    msg.set_content(plain_body)
    msg.add_alternative(html_body, subtype='html')

    # attach full alert JSON for traceability
    try:
        json_bytes = json.dumps(alert, indent=2).encode('utf-8')
        msg.add_attachment(json_bytes, maintype='application', subtype='json', filename='alert.json')
    except Exception:
        pass

    if dry_run or not cfg.get('host') or not to_addrs:
        logger.info(
            "email dry-run alert_type=%s severity=%s to=%s",
            alert.get("alert_type"),
            alert.get("severity"),
            list(to_addrs or []),
        )
        if _RICH_AVAILABLE and _console:
            _console.print(
                f"[bold yellow][EMAIL DRY-RUN][/bold yellow] "
                f"[white]alert_type={alert.get('alert_type')} "
                f"severity={alert.get('severity')} "
                f"to={list(to_addrs or [])}[/white]"
            )
        print("[EMAIL-DRY-RUN] To:", msg['To'])
        print("[EMAIL-DRY-RUN] Subject:", msg['Subject'])
        print("[EMAIL-DRY-RUN] Body:\n")
        print(plain_body)
        return msg

    # send via SMTP with retry/backoff
    host = cfg.get('host')
    port = cfg.get('port') or 25
    user = cfg.get('user')
    password = cfg.get('password')

    attempt = 0
    last_error = None
    while attempt <= max_retries:
        attempt += 1
        try:
            logger.info(
                "sending email attempt=%s/%s host=%s port=%s to=%s alert_type=%s severity=%s",
                attempt,
                max_retries,
                host,
                port,
                list(to_addrs or []),
                alert.get("alert_type"),
                alert.get("severity"),
            )
            if _RICH_AVAILABLE and _console:
                _console.print(
                    f"[bold blue][EMAIL][/bold blue] "
                    f"[cyan]attempt {attempt}/{max_retries}[/cyan] "
                    f"host={host} port={port} "
                    f"to={list(to_addrs or [])} "
                    f"alert_type={alert.get('alert_type')} "
                    f"severity={alert.get('severity')}"
                )
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                s.ehlo()
                if s.has_extn('STARTTLS'):
                    s.starttls()
                    s.ehlo()
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
            logger.info(
                "email sent attempt=%s host=%s to=%s alert_type=%s severity=%s",
                attempt,
                host,
                list(to_addrs or []),
                alert.get("alert_type"),
                alert.get("severity"),
            )
            if _RICH_AVAILABLE and _console:
                _console.print(
                    f"[bold green][EMAIL SENT][/bold green] "
                    f"[white]attempt={attempt} host={host} "
                    f"to={list(to_addrs or [])} "
                    f"alert_type={alert.get('alert_type')} "
                    f"severity={alert.get('severity')}[/white]"
                )
            return True
        except Exception as e:
            last_error = e
            logger.error(
                "email send failed attempt=%s/%s host=%s to=%s error=%s",
                attempt,
                max_retries,
                host,
                list(to_addrs or []),
                str(e),
            )
            if _RICH_AVAILABLE and _console:
                _console.print(
                    f"[bold red][EMAIL ERROR][/bold red] "
                    f"[white]attempt={attempt}/{max_retries} host={host} "
                    f"to={list(to_addrs or [])} "
                    f"error={str(e)}[/white]"
                )
            if attempt > max_retries:
                break
            sleep_for = backoff_seconds * attempt
            time.sleep(sleep_for)

    print("[EMAIL-ERROR]", last_error)
    return False
