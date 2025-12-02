import re
from base_parser import BaseParser

class ApacheParser(BaseParser):
    def parse_line(self, line):
        """Extract IP, timestamp, method, path, and status."""
        
        ip = self.extract_ip(line)

        # Extract timestamp: [12/Feb/2025:14:20:33 +0100]
        ts_match = re.search(r'\[(.*?)\]', line)
        timestamp = ts_match.group(1) if ts_match else None

        # Extract method and path: "GET /home HTTP/1.1"
        req_match = re.search(r'"(\w+)\s+([^"]+)\s+HTTP', line)
        if req_match:
            method = req_match.group(1)
            path = req_match.group(2)
        else:
            method = None
            path = None

        # Extract status code (200, 404, 500…)
        status_match = re.search(r'"\s+(\d{3})\s+', line)
        status = status_match.group(1) if status_match else None

        return {
            "raw": line,
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "status": status,
        }
