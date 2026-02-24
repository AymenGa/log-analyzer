import os

from Analytics.frequency import FrequencyAnalyzer


def test_frequency_analyzer_top_ips_and_users():
    events = [
        {"ip": "1.1.1.1", "user": "alice"},
        {"ip": "1.1.1.1", "user": "alice"},
        {"ip": "2.2.2.2", "user": "bob"},
        {"ip": "1.1.1.1", "user": "carol"},
    ]

    fa = FrequencyAnalyzer(events)

    top_ips = fa.top_ips()
    assert top_ips[0] == ("1.1.1.1", 3)

    top_users = fa.top_users()
    # alice appears twice, bob and carol once
    assert ("alice", 2) in top_users

