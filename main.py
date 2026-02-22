import argparse
from parser.unified_parser import UnifiedParser
from Analytics.frequency import FrequencyAnalyzer
from Analytics.detection import SecurityDetector
from Analytics.alerts import AlertEngine
from monitor import monitor


def analysis_mode(path):
    up = UnifiedParser(path)
    events = up.parse()

    fa = FrequencyAnalyzer(events)
    print("\nFrequency: top IPs")
    for ip, count in fa.top_ips(5):
        print(f" - {ip}: {count}")

    sd = SecurityDetector(events)
    ae = AlertEngine(sd)
    ae.generate_bruteforce_alerts(threshold=3)
    ae.generate_suspicious_user_alerts(threshold=3)
    alerts = ae.get_alerts()
    if alerts:
        print("\nAlerts:")
        for a in alerts:
            print(a)
    else:
        print("No alerts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analyzer CLI")
    parser.add_argument("--file", help="Analyze file once")
    parser.add_argument("--monitor", help="Monitor file live")
    parser.add_argument("--window", type=int, default=60, help="Time-window seconds for live mode")
    parser.add_argument("--threshold", type=int, default=3, help="Attempts threshold for time-window alerts")
    parser.add_argument("--show-frequency", action="store_true", help="Show frequency alerts in live monitor")
    args = parser.parse_args()

    if args.file:
        analysis_mode(args.file)
    elif args.monitor:
        monitor(args.monitor, time_window_seconds=args.window, time_window_threshold=args.threshold, show_frequency=args.show_frequency)
    else:
        parser.print_help()
