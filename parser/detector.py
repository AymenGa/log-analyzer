import re
from parser.apache_parser import ApacheParser
from parser.linux_auth_parser import LinuxAuthParser

class LogDetector:
    def __init__(self, filepath):
        self.filepath = filepath

    def detect(self):
        """Detect log format by reading first lines."""
        with open(self.filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()

                # Apache example: "IP - - [DATE] "METHOD PATH HTTP"
                if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b - - \[', line):
                    return ApacheParser(self.filepath)

                # Linux auth.log example: "Nov 27 12:00:01 server sshd[...]"
                if re.match(r'^\w+\s+\d+\s+\d+:\d+:\d+', line):
                    return LinuxAuthParser(self.filepath)

        return None
