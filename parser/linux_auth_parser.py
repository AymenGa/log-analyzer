import re
from base_parser import BaseParser

class LinuxAuthParser(BaseParser):
    def parse_line(self, line):
        """Parse SSH authentication logs."""

        ip = self.extract_ip(line)

        # Timestamp (e.g. "Nov 27 12:00:01")
        ts_match = re.match(r'^\w+\s+\d+\s+\d+:\d+:\d+', line)
        timestamp = ts_match.group(0) if ts_match else None

        # Failed or accepted password
        if "Failed password" in line:
            event = "failed_login"
        elif "Accepted password" in line:
            event = "successful_login"
        else:
            event = None

        # Extract username
        user_match = re.search(r'for\s+(\w+)', line)
        username = user_match.group(1) if user_match else None

        return {
            "raw": line,
            "timestamp": timestamp,
            "ip": ip,
            "event": event,
            "username": username
        }
