import re
from collections import Counter
import argparse

def parse_log(file_path):
    ips = []
    failed_logins = 0

    with open(file_path, 'r') as f:
        for line in f:
            if "Failed password" in line:
                failed_logins += 1

                # extract IP address using regex
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    ips.append(ip_match.group())

    print("\n======= LOG SUMMARY =======")
    print(f"Total failed logins: {failed_logins}\n")

    print("Top IPs causing failures:")
    for ip, count in Counter(ips).most_common(5):
        print(f" - {ip} → {count} attempts")

# CLI entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Log Analyzer CLI")
    parser.add_argument("--file", required=True, help="Path to log file")
    args = parser.parse_args()

    parse_log(args.file)
