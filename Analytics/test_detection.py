from parser.unified_parser import UnifiedParser
from Analytics.detection import SecurityDetector

up = UnifiedParser("logs/sample_auth.log")
events = up.parse()

detector = SecurityDetector(events)

print("Brute-force IPs:", detector.detect_bruteforce_ips())
print("Suspicious users:", detector.detect_suspicious_users())
