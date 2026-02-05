from parser.detector import LogDetector

class UnifiedParser:
    """
    Converts any supported log into a unified dictionary format:
    timestamp, ip, event, user, method, url, status, size
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.parser = LogDetector(filepath).detect()

    def parse(self):
        """Return a list of dictionaries in standard format"""
        results = []

        if self.parser is None:
            print("No parser detected for this file.")
            return results

        for line in self.parser.read_lines():
            parsed = self.parser.parse_line(line)
            if parsed is None:
                continue

            # unified structure
            unified = {
                "timestamp": parsed.get("timestamp"),
                "ip": parsed.get("ip"),
                "event_type": parsed.get("event"),  
                "user": parsed.get("username"),
                "method": parsed.get("method"),
                "url": parsed.get("path") ,
                "status": parsed.get("status"),
                "size": parsed.get("size")
            }

            results.append(unified)

        return results
