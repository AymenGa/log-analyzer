import os
import json


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


def load_config():
    try:
        with open(config_path(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: dict):
    with open(config_path(), 'w', encoding='utf-8') as f:
        json.dump(cfg or {}, f, indent=2)
