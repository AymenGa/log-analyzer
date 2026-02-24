from Analytics.detection import SecurityDetector


def make_event(ip: str, user: str, ts: str, event_type: str = "failed_login"):
    return {"ip": ip, "user": user, "timestamp": ts, "event_type": event_type}


def test_detect_bruteforce_ips_frequency():
    events = [
        make_event("10.0.0.1", "alice", "Nov 27 12:00:00"),
        make_event("10.0.0.1", "alice", "Nov 27 12:00:10"),
        make_event("10.0.0.2", "bob", "Nov 27 12:00:20"),
    ]
    sd = SecurityDetector(events)

    result = sd.detect_bruteforce_ips(threshold=2)
    assert result == {"10.0.0.1": 2}


def test_detect_suspicious_users_frequency():
    events = [
        make_event("10.0.0.1", "alice", "Nov 27 12:00:00"),
        make_event("10.0.0.2", "alice", "Nov 27 12:00:10"),
        make_event("10.0.0.3", "bob", "Nov 27 12:00:20"),
    ]
    sd = SecurityDetector(events)

    result = sd.detect_suspicious_users(threshold=2)
    assert result == {"alice": 2}


def test_detect_bruteforce_time_window_ip():
    # three attempts for same IP within 30 seconds should trigger
    events = [
        make_event("10.0.0.9", "alice", "Nov 27 12:00:00"),
        make_event("10.0.0.9", "alice", "Nov 27 12:00:10"),
        make_event("10.0.0.9", "alice", "Nov 27 12:00:20"),
    ]
    sd = SecurityDetector(events)

    alerts = sd.detect_bruteforce_time_window(threshold=3, window_seconds=60)
    assert "10.0.0.9" in alerts
    assert alerts["10.0.0.9"]["count"] == 3


def test_detect_suspicious_users_time_window_user():
    # three failed logins for same user within 30 seconds should trigger
    events = [
        make_event("10.0.0.1", "alice", "Nov 27 12:00:00"),
        make_event("10.0.0.2", "alice", "Nov 27 12:00:10"),
        make_event("10.0.0.3", "alice", "Nov 27 12:00:20"),
    ]
    sd = SecurityDetector(events)

    alerts = sd.detect_suspicious_users_time_window(threshold=3, window_seconds=60)
    assert "alice" in alerts
    assert alerts["alice"]["count"] == 3

