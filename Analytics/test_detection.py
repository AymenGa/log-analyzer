from parser.unified_parser import UnifiedParser
from Analytics.detection import SecurityDetector

# Parse Linux authentication log
up = UnifiedParser("logs/sample_auth.log")
events = up.parse()

print("EVENTS:")
for e in events:
    print(e)

detector = SecurityDetector(events)

print("\nBrute-force IPs (frequency):",
      detector.detect_bruteforce_ips(threshold=2))

print("Brute-force IPs (time window):",
      detector.detect_bruteforce_time_window(
          threshold=3,
          window_seconds=120
      ))

print("Suspicious users (frequency):",
      detector.detect_suspicious_users(threshold=2))

print("Suspicious users (time window):",
      detector.detect_suspicious_users_time_window(
          threshold=3,
          window_seconds=60
      ))
