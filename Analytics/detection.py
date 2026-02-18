from collections import Counter
from datetime import datetime, timedelta

def parse_time(ts):
    """Parse timestamps like 'Nov 27 12:01:12' into datetime objects."""
    return datetime.strptime(ts, "%b %d %H:%M:%S")

class SecurityDetector:
    def __init__(self, events):
        self.events = events

    # -----------------------------
    # Frequency-based detections
    # -----------------------------
    def detect_bruteforce_ips(self, threshold=3):
        failed_ips = [e["ip"] for e in self.events if e.get("event_type") == "failed_login"]
        counter = Counter(failed_ips)
        return {ip: count for ip, count in counter.items() if count >= threshold}

    def detect_suspicious_users(self, threshold=3):
        users = [e.get("user") for e in self.events if e.get("event_type") == "failed_login" and e.get("user")]
        counter = Counter(users)
        return {user: count for user, count in counter.items() if count >= threshold}

    # -----------------------------
    # Time-window brute-force detection
    # -----------------------------
    def detect_bruteforce_time_window(self, threshold=3, window_seconds=120):
        """
        Detect brute-force attacks based on:
        - same IP
        - multiple failed logins
        - within a short time window
        """
        # Keep only failed login events with timestamps
        failed_events = [e for e in self.events if e.get("event_type") == "failed_login" and e.get("timestamp")]

        # Group attempts by IP
        attempts_by_ip = {}
        for e in failed_events:
            ip = e["ip"]
            time = parse_time(e["timestamp"])
            attempts_by_ip.setdefault(ip, []).append(time)

        alerts = {}
        for ip, times in attempts_by_ip.items():
            times.sort()
            for i in range(len(times)):
                j = i + threshold - 1
                if j < len(times):
                    delta = (times[j] - times[i]).total_seconds()
                    if delta <= window_seconds:
                        alerts[ip] = threshold
                        break
        return alerts
