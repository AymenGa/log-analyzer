from datetime import datetime


class AlertEngine:
    def __init__(self, detector):
        """
        detector: instance of SecurityDetector
        """
        self.detector = detector
        self.alerts = []

    def generate_bruteforce_alerts(self, threshold=3):
        results = self.detector.detect_bruteforce_ips(threshold)

        for ip, count in results.items():
            self.alerts.append({
                "alert_type": "BruteForceAttack",
                "source_ip": ip,
                "severity": "HIGH",
                "evidence": {
                    "failed_attempts": count
                },
                "timestamp": datetime.utcnow().isoformat()
            })

    def generate_suspicious_user_alerts(self, threshold=3):
        results = self.detector.detect_suspicious_users(threshold)

        for user, count in results.items():
            self.alerts.append({
                "alert_type": "SuspiciousUserActivity",
                "user": user,
                "severity": "MEDIUM",
                "evidence": {
                    "failed_attempts": count
                },
                "timestamp": datetime.utcnow().isoformat()
            })

    def generate_suspicious_user_time_window_alerts(self, threshold=3, window_seconds=60):
        results = self.detector.detect_suspicious_users_time_window(threshold=threshold, window_seconds=window_seconds)

        for user, info in results.items():
            self.alerts.append({
                "alert_type": "SuspiciousUserTimeWindow",
                "user": user,
                "severity": "HIGH" if info["count"] >= (threshold * 2) else "MEDIUM",
                "evidence": {
                    "failed_attempts": info["count"],
                    "duration_seconds": info["duration_seconds"]
                },
                "timestamp": datetime.utcnow().isoformat()
            })

    def get_alerts(self):
        return self.alerts
