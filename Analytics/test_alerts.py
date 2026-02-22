from parser.unified_parser import UnifiedParser
from Analytics.detection import SecurityDetector

# Parse Linux auth log
up = UnifiedParser("logs/sample_auth.log")
events = up.parse()

detector = SecurityDetector(events)

print("Brute-force IPs (frequency):", detector.detect_bruteforce_ips(threshold=2))
print("Brute-force IPs (time window):", detector.detect_bruteforce_time_window(threshold=2, window_seconds=180))
print("Suspicious users:", detector.detect_suspicious_users(threshold=2))
