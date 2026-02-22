from collections import Counter
from datetime import datetime, timedelta

def parse_time(ts):
    """Parse timestamps like 'Nov 27 12:01:12' into datetime objects."""
    # Syslog timestamps do not contain a year; assume current year for comparisons
    dt = datetime.strptime(ts, "%b %d %H:%M:%S")
    return dt.replace(year=datetime.utcnow().year)

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

    def detect_suspicious_users_time_window(self, threshold=3, window_seconds=60):
        """
        Detect suspicious users by counting failed_login events per username
        within a sliding time window. Returns concise dict mapping user -> {count, duration_seconds}.
        """
        failed_events = [e for e in self.events if e.get("event_type") == "failed_login" and e.get("timestamp") and e.get("user")]

        attempts_by_user = {}
        for e in failed_events:
            user = e["user"]
            time = parse_time(e["timestamp"])
            attempts_by_user.setdefault(user, []).append(time)

        alerts = {}
        for user, times in attempts_by_user.items():
            times.sort()
            max_count = 0
            best_window = None

            for i in range(len(times)):
                j = i
                while j < len(times) and (times[j] - times[i]).total_seconds() <= window_seconds:
                    j += 1

                count = j - i
                if count > max_count:
                    max_count = count
                    best_window = (times[i], times[j-1]) if j - 1 >= i else (times[i], times[i])

            if max_count >= threshold:
                duration = (best_window[1] - best_window[0]).total_seconds() if best_window else 0
                alerts[user] = {
                    "count": max_count,
                    "duration_seconds": int(duration)
                }

        return alerts

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
            max_count = 0
            best_window = None

            # sliding window: for each start index, expand to include all within window_seconds
            for i in range(len(times)):
                j = i
                while j < len(times) and (times[j] - times[i]).total_seconds() <= window_seconds:
                    j += 1

                count = j - i
                if count > max_count:
                    max_count = count
                    best_window = (times[i], times[j-1]) if j - 1 >= i else (times[i], times[i])

            if max_count >= threshold:
                # return concise info: number of attempts and duration in seconds
                duration = (best_window[1] - best_window[0]).total_seconds() if best_window else 0
                alerts[ip] = {
                    "count": max_count,
                    "duration_seconds": int(duration)
                }

        return alerts
