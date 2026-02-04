from collections import Counter

class SecurityDetector:
    def __init__(self, events):
        self.events = events

    def detect_bruteforce_ips(self, threshold=3):
        failed_ips = [
            e["ip"] for e in self.events
            if e.get("event_type") == "failed_login"
        ]
        counter = Counter(failed_ips)
        return {ip: count for ip, count in counter.items() if count >= threshold}

    def detect_suspicious_users(self, threshold=3):
        users = [
            e.get("user") for e in self.events
            if e.get("event_type") == "failed_login"
        ]
        counter = Counter(users)
        return {user: count for user, count in counter.items() if count >= threshold}

    def detect_high_frequency_ips(self, threshold=5):
        ips = [e["ip"] for e in self.events]
        counter = Counter(ips)
        return {ip: count for ip, count in counter.items() if count >= threshold}
