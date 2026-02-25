## Overview

`log-analyzer` is a CLI tool that:

- **Parses web and Linux auth logs** (Apache + `/var/log/auth.log`–style).
- Builds a **unified event stream** (IPs, usernames, URLs, timestamps).
- Runs **frequency** and **time-window** based detections for:
  - brute-force attacks (per IP),
  - suspicious user activity (per username).
- Streams **live alerts** in the terminal with a Rich UI and **optional email notifications**.
- Can **export alerts as JSON** for later analysis (`alerts.json`, `batch_alerts.json`, `live_alerts.json`).

It’s structured around phases (1–6)

## Installation (local)

### Using pip from the repo

From the project root:

```bash
pip install .
```

This installs a `log-analyzer` CLI on your PATH.

### Dev environment

If you prefer, install dev dependencies:

```bash
pip install -r requirements.txt
```

and run with:

```bash
python main.py --help
```

## Quickstart: batch analysis (local)

Analyze a single log file (e.g. the sample auth log) and export alerts:

```bash
log-analyzer --file logs/sample_auth.log --alerts-json batch_alerts.json
```

You’ll get:

- A **frequency summary** of top IPs.
- **Rich-rendered alert panels** (by IP and by user) with severity + risk score.
- A small **severity dashboard**.
- A JSON file `batch_alerts.json` with all computed alerts.

If you omit `--alerts-json`, alerts are written to a per-user file under:

- Windows: `%APPDATA%\log-analyzer\alerts.json`
- Linux/macOS: `~/.log-analyzer/alerts.json`

## Quickstart: live monitoring (local)

Monitor a log file in real time:

```bash
log-analyzer \
  --monitor logs/sample_auth.log \
  --window 60 \
  --threshold 3 \
  --alerts-json live_alerts.json
```

Then **new log lines appears** (failed logins, etc.) in `logs/sample_auth.log`.  
You’ll see:

- `[INFO] Failed login ...` lines.
- Time-window alerts like `BruteForceAttackTimeWindow` and `SuspiciousUserTimeWindow`.
- If email is configured, **colored email status lines** (`[EMAIL]`, `[EMAIL SENT]`, `[EMAIL ERROR]`).
- Alerts incrementally written to `live_alerts.json`.

### SMTP / email configuration

You can configure SMTP in two ways:

- **One-off test**:

  ```bash
  log-analyzer --email-test \
    --smtp-host smtp.gmail.com \
    --smtp-port 587 \
    --smtp-user your@gmail.com \
    --smtp-pass "YOUR_APP_PASSWORD" \
    --email-from your@gmail.com \
    --email-to you@example.com
  ```

- **Interactive dashboard**: run a live monitor once, the UI will offer to register email alerts, and credentials are stored securely using the OS keyring (not in plaintext).

## Running with Docker

You have **three simple options**:

- **Local Python**: `python main.py --file ...` or `--monitor ...` (described above).
- **One‑off Docker containers** (interactive, you choose JSON filenames).
- **Docker Compose services** (non‑interactive, fixed JSON filenames).

### Option 1 – One‑off Docker (interactive)

From the project root:

- **Live monitoring (you choose alerts JSON name)**:

  ```bash
  docker run -it --rm \
    -e SMTP_HOST="smtp.gmail.com" \
    -e SMTP_PORT="587" \
    -e SMTP_USER="your@gmail.com" \
    -e SMTP_PASS="your_app_password" \
    -e EMAIL_FROM="your@gmail.com" \
    -e EMAIL_TO="your-recipient@example.com" \
    -v "$(pwd)/logs:/logs:ro" \
    -v "$(pwd):/app" \
    log-analyzer \
    python main.py --monitor /logs/sample_auth.log
  ```

  The app will **ask you**:

  - `Alerts JSON output file (Enter for default: ...)`

- **Batch analysis (you choose alerts + frequency JSON names)**:

  ```bash
  docker run -it --rm \
    -v "$(pwd)/logs:/logs:ro" \
    -v "$(pwd):/app" \
    log-analyzer \
    python main.py --file /logs/sample_auth.log
  ```

  The app will **ask you**:

  - `Alerts JSON output file (Enter for default: ...)`
  - `Frequency JSON output file (leave blank to skip, or enter name):`

### Option 2 – Docker Compose (monitoring)

`Docker-compose.yml` defines a `log-analyzer` service that:

- Runs in **monitor** mode (`MODE=monitor`).
- Reads `LOG_FILE` from `/logs` (host `./logs` mounted read‑only).
- Uses SMTP env vars from the compose file.
- Writes live alerts to a **fixed file**: `/app/live_alerts.json`.

Usage:

```bash
docker compose up --build log-analyzer
```

- Alerts stream in the container logs.
- `live_alerts.json` is written inside the container (mount `/app` if you want it on the host).

### Option 3 – Docker Compose (batch)

The `log-analyzer-batch` service in `Docker-compose.yml`:

- Runs in **batch** mode (`MODE=file`).
- Reads `/logs/sample_auth.log`.
- Writes:
  - `/app/batch_alerts.json` – all computed alerts.
  - `/app/batch_frequency.json` – frequency stats (top IPs/users/URLs).
- Mounts the project directory to `/app`, so these JSON files appear in your project folder.

Usage:

```bash
docker compose up --build log-analyzer-batch
```

When it finishes, check `batch_alerts.json` and `batch_frequency.json` in the project root.

## Tests & CI

- Run tests locally:

  ```bash
  pytest
  ```

- GitHub Actions workflow (`.github/workflows/ci.yml`) automatically:
  - installs dependencies from `requirements.txt`,
  - runs `pytest` on every push / pull request to `main`.

