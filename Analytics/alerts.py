from datetime import datetime


class AlertEngine:
    def __init__(self, detector):
        """
        detector: instance of SecurityDetector
        """
        self.detector = detector
        self.alerts = []
        # simple seen set to avoid duplicate notifications: (alert_type, identifier)
        self._seen = set()
        # notifier callback (callable(alert_dict)) - by default prints to console
        self.notifier = self._console_notify

    def generate_bruteforce_alerts(self, threshold=3):
        results = self.detector.detect_bruteforce_ips(threshold)

        for ip, count in results.items():
            alert = {
                "alert_type": "BruteForceAttack",
                "source_ip": ip,
                "evidence": {"failed_attempts": count},
                "timestamp": datetime.utcnow().isoformat()
            }
            self._apply_risk(alert)
            self.alerts.append(alert)

    def generate_suspicious_user_alerts(self, threshold=3):
        results = self.detector.detect_suspicious_users(threshold)

        for user, count in results.items():
            alert = {
                "alert_type": "SuspiciousUserActivity",
                "user": user,
                "evidence": {"failed_attempts": count},
                "timestamp": datetime.utcnow().isoformat()
            }
            self._apply_risk(alert)
            self.alerts.append(alert)

    def generate_suspicious_user_time_window_alerts(self, threshold=3, window_seconds=60):
        results = self.detector.detect_suspicious_users_time_window(threshold=threshold, window_seconds=window_seconds)

        for user, info in results.items():
            alert = {
                "alert_type": "SuspiciousUserTimeWindow",
                "user": user,
                "evidence": {
                    "failed_attempts": info["count"],
                    "duration_seconds": info["duration_seconds"]
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            self._apply_risk(alert)
            self.alerts.append(alert)

    def generate_bruteforce_time_window_alerts(self, threshold=3, window_seconds=120):
        """Generate alerts for IPs detected by time-window brute-force logic."""
        results = self.detector.detect_bruteforce_time_window(threshold=threshold, window_seconds=window_seconds)
        for ip, info in results.items():
            alert = {
                "alert_type": "BruteForceTimeWindow",
                "source_ip": ip,
                "evidence": {
                    "failed_attempts": info.get("count"),
                    "duration_seconds": info.get("duration_seconds")
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            self._apply_risk(alert)
            self.alerts.append(alert)

    def generate_all_alerts(self, freq_threshold=2, time_window_threshold=3, time_window_seconds=120):
        """Convenience method to generate all alert types (frequency + time-window for IPs and users)."""
        # frequency-based
        self.generate_bruteforce_alerts(threshold=freq_threshold)
        self.generate_suspicious_user_alerts(threshold=freq_threshold)
        # time-window based
        self.generate_bruteforce_time_window_alerts(threshold=time_window_threshold, window_seconds=time_window_seconds)
        self.generate_suspicious_user_time_window_alerts(threshold=time_window_threshold, window_seconds=time_window_seconds)

    def get_alerts(self):
        return self.alerts

    def _console_notify(self, alert):
        # delegate to rich-based renderer if available
        try:
            from Analytics.ui import render_alert
            render_alert(alert, pretty=True)
        except Exception:
            # fallback to simple print
            atype = alert.get("alert_type")
            sev = alert.get("severity")
            ts = alert.get("timestamp")
            if alert.get("source_ip"):
                idn = alert.get("source_ip")
            else:
                idn = alert.get("user")

            # build message
            details = []
            ev = alert.get("evidence", {})
            if "failed_attempts" in ev:
                details.append(f"attempts={ev['failed_attempts']}")
            if "duration_seconds" in ev:
                details.append(f"duration={ev['duration_seconds']}s")

            print(f"[ALERT][{sev}] {atype} | id={idn} | {' '.join(details)} | {ts}")

    def _apply_risk(self, alert):
        """
        Compute a numeric `risk_score` (0-100) for the alert and set `severity`.

        Heuristic used:
        - Base contribution from number of failed attempts: `count * 12`
        - Shorter duration (many attempts in short time) increases risk: `(60 - duration_seconds) * 2`
        - Cap score at 100.

        Mapping:
        - score >= 70 -> HIGH
        - score >= 40 -> MEDIUM
        - otherwise -> LOW
        """
        ev = alert.get("evidence", {})
        count = int(ev.get("failed_attempts", 0))
        duration = ev.get("duration_seconds")

        if duration is None:
            duration = 60

        try:
            duration = float(duration)
        except Exception:
            duration = 60.0

        # shorter duration -> higher score
        dur_factor = max(0.0, 60.0 - duration)
        score = int(min(100, count * 12 + dur_factor * 2))

        alert["risk_score"] = score
        if score >= 70:
            alert["severity"] = "HIGH"
        elif score >= 40:
            alert["severity"] = "MEDIUM"
        else:
            alert["severity"] = "LOW"

    def process_event(self, event, time_window_threshold=3, time_window_seconds=60, freq_threshold=10, show_frequency=False):
        """
        Process a single unified event (dict). Appends to detector events and runs time-window detection.
        Notifies on newly observed alerts.
        """
        # append event to detector state
        self.detector.events.append(event)

        # print informational line for failed logins
        if event.get("event_type") == "failed_login":
            user = event.get("user")
            ip = event.get("ip")
            print(f"[INFO] Failed login | user={user} | ip={ip} | ts={event.get('timestamp')}")

        # run time-window detections (IP)
        ip_alerts = self.detector.detect_bruteforce_time_window(threshold=time_window_threshold, window_seconds=time_window_seconds)
        for ip, info in ip_alerts.items():
            key = ("BruteForceTimeWindow", ip)
            if key in self._seen:
                continue
            self._seen.add(key)
            alert = {
                "alert_type": "BruteForceAttackTimeWindow",
                "source_ip": ip,
                "severity": "HIGH",
                "evidence": {
                    "failed_attempts": info.get("count"),
                    "duration_seconds": info.get("duration_seconds")
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            self.alerts.append(alert)
            self.notifier(alert)

        # run time-window user detections
        user_alerts = self.detector.detect_suspicious_users_time_window(threshold=time_window_threshold, window_seconds=time_window_seconds)
        for user, info in user_alerts.items():
            key = ("SuspiciousUserTimeWindow", user)
            if key in self._seen:
                continue
            self._seen.add(key)
            alert = {
                "alert_type": "SuspiciousUserTimeWindow",
                "user": user,
                "severity": "HIGH",
                "evidence": {
                    "failed_attempts": info.get("count"),
                    "duration_seconds": info.get("duration_seconds")
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            self.alerts.append(alert)
            self.notifier(alert)

        # optionally, run light frequency check for immediate notable counts (capped)
        # in live monitor we typically suppress frequency alerts unless explicitly requested
        if show_frequency:
            freq_ips = self.detector.detect_bruteforce_ips(threshold=freq_threshold)
            for ip, count in freq_ips.items():
                key = ("BruteForceFrequency", ip)
                if key in self._seen:
                    continue
                self._seen.add(key)
                alert = {
                    "alert_type": "BruteForceAttackFrequency",
                    "source_ip": ip,
                    "evidence": {"failed_attempts": count},
                    "timestamp": datetime.utcnow().isoformat()
                }
                self._apply_risk(alert)
                self.alerts.append(alert)
                self.notifier(alert)
