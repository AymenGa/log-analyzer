import os
import json

try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    keyring = None
    KEYRING_AVAILABLE = False

_SMTP_SERVICE = "log-analyzer-smtp"


def _get_base_dir():
    # Prefer APPDATA on Windows, otherwise use home dir
    appdata = os.getenv('APPDATA')
    if appdata:
        base = os.path.join(appdata, 'log-analyzer')
    else:
        base = os.path.join(os.path.expanduser('~'), '.log-analyzer')
    os.makedirs(base, exist_ok=True)
    return base


def config_path():
    return os.path.join(_get_base_dir(), 'config.json')


def alerts_path():
    """Return the path where alerts JSON will be stored."""
    return os.path.join(_get_base_dir(), 'alerts.json')


def _smtp_key(user: str | None, host: str | None) -> str:
    """Build a stable keyring identifier for SMTP credentials."""
    user_part = (user or "").strip()
    host_part = (host or "").strip()
    return f"{user_part}@{host_part}" if host_part else user_part


def save_smtp_password(user: str | None, host: str | None, password: str | None):
    """Persist the SMTP password in the OS keyring (if available)."""
    if not (KEYRING_AVAILABLE and password):
        return
    try:
        keyring.set_password(_SMTP_SERVICE, _smtp_key(user, host), password)
    except Exception:
        # If keyring backend fails, we silently skip; caller should handle fallbacks.
        pass


def load_smtp_password(user: str | None, host: str | None) -> str | None:
    """Load the SMTP password from the OS keyring, if available."""
    if not KEYRING_AVAILABLE:
        return None
    try:
        return keyring.get_password(_SMTP_SERVICE, _smtp_key(user, host))
    except Exception:
        return None


def load_config():
    try:
        with open(config_path(), 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        return {}

    # One-time migration: if a plaintext SMTP password is present in config,
    # move it into the keyring and strip it from the file.
    try:
        smtp = (cfg or {}).get('smtp') or {}
        pwd = smtp.get('password')
        host = smtp.get('host')
        user = smtp.get('user')
        if pwd and host:
            save_smtp_password(user, host, pwd)
            smtp['password'] = None
            cfg['smtp'] = smtp
            save_config(cfg)
    except Exception:
        # On any error, return the original cfg without crashing the caller.
        return cfg

    return cfg


def save_config(cfg: dict):
    with open(config_path(), 'w', encoding='utf-8') as f:
        json.dump(cfg or {}, f, indent=2)
