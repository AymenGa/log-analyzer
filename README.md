# 🔍 Log Analyzer — Real-Time Security Monitoring Tool

A Python CLI tool that detects suspicious activity in web server and Linux authentication logs — built for security auditing and threat detection.

## ✨ Features

- 🕵️ **Parses Apache & Linux auth logs** (`/var/log/auth.log`)
- 🚨 **Detects brute-force attacks** by IP and username
- ⏱️ **Real-time monitoring** with live alert streaming
- 📊 **Rich terminal UI** with severity dashboard
- 📧 **Email notifications** via SMTP (Gmail supported)
- 🐳 **Docker & Docker Compose** support
- 📁 **JSON export** of all alerts for further analysis
- ✅ **CI/CD** with GitHub Actions

## 🚀 Quick Start

### Install
```bash
pip install .
# or for development
pip install -r requirements.txt
```

### Batch Analysis
```bash
log-analyzer --file logs/sample_auth.log --alerts-json alerts.json
```

### Live Monitoring
```bash
log-analyzer --monitor logs/sample_auth.log --window 60 --threshold 3
```

### Docker
```bash
docker compose up --build log-analyzer
```

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-green)

- Python, Rich, Docker, Docker Compose
- GitHub Actions for automated testing

## 📁 Project Structure
```
log-analyzer/
├── parser/       # Log parsers (Apache, auth.log)
├── Analytics/    # Detection algorithms
├── cli/          # CLI interface
├── notifiers/    # Email alert system
├── logs/         # Sample log files
└── tests/        # Pytest test suite
```

## 🧪 Tests
```bash
pytest
```

## 👨‍💻 Author

**Aymen Gasri** — Computer Engineering Graduate | Cybersecurity Enthusiast

[![LinkedIn](https://img.shields.io/badge/LinkedIn-blue?logo=linkedin)](https://linkedin.com/in/aymengasri)
[![GitHub](https://img.shields.io/badge/GitHub-black?logo=github)](https://github.com/AymenGa)
