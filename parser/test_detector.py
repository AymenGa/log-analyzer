from detector import LogDetector

detector = LogDetector("../logs/apache_sample.log")
parser = detector.detect()

print("Detected parser:", type(parser).__name__)

for line in parser.read_lines():
    print(parser.parse_line(line))
