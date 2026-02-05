from parser.unified_parser import UnifiedParser
from Analytics.detection import SecurityDetector
from Analytics.alerts import AlertEngine

# Parse Linux auth log
up = UnifiedParser("logs/sample_auth.log")
events = up.parse()

detector = SecurityDetector(events)
engine = AlertEngine(detector)

engine.generate_bruteforce_alerts(threshold=2)
engine.generate_suspicious_user_alerts(threshold=2)

for alert in engine.get_alerts():
    print(alert)
