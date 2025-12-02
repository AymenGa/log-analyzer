import re

class BaseParser:
    def __init__(self, filepath):
        self.filepath = filepath

    def read_lines(self):
        """Read file line by line."""
        with open(self.filepath, "r", errors="ignore") as f:
            for line in f:
                yield line.strip()

    def extract_ip(self, line):
        """Find first IPv4 address in a line."""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(pattern, line)
        if match:
            return match.group(0)
        return None

    def extract_timestamp(self, line):
        """To be overridden later."""
        return None

    def parse_line(self, line):
        """To be overridden in child parsers."""
        return None
