from parser.unified_parser import UnifiedParser
from Analytics.frequency import FrequencyAnalyzer

# Parse Apache log
up = UnifiedParser("logs/apache_sample.log")
logs = up.parse()

analyzer = FrequencyAnalyzer(logs)
print("Top IPs:", analyzer.top_ips())
print("Top URLs:", analyzer.top_urls())

# Parse Linux auth log
up2 = UnifiedParser("logs/sample_auth.log")
logs2 = up2.parse()
analyzer2 = FrequencyAnalyzer(logs2)
print("\nTop IPs (auth):", analyzer2.top_ips())
print("Top users (auth):", analyzer2.top_users())