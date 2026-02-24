import os
import smtplib
from email.message import EmailMessage
import json


def email_notifier(alert, smtp_config=None, dry_run=True, timeout=10):
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
        print("[EMAIL-DRY-RUN] To:", msg['To'])
        print("[EMAIL-DRY-RUN] Subject:", msg['Subject'])
        print("[EMAIL-DRY-RUN] Body:\n")
        print(body)
        return msg

    # send via SMTP
    host = cfg.get('host')
    port = cfg.get('port') or 25
    user = cfg.get('user')
    password = cfg.get('password')

    try:
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.ehlo()
            if s.has_extn('STARTTLS'):
                s.starttls()
                s.ehlo()
            if user and password:
                s.login(user, password)
            s.send_message(msg)
        return True
    except Exception as e:
        print("[EMAIL-ERROR]", e)
        return False
