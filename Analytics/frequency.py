from collections import Counter

class FrequencyAnalyzer:
    """
    Analyze a list of unified log dictionaries.
    Can return top N IPs, top N users, or top URLs.
    """

    def __init__(self, logs):
        self.logs = logs

    def top_ips(self, n=5):
        ips = [entry['ip'] for entry in self.logs if entry.get('ip')]
        counter = Counter(ips)
        return counter.most_common(n)

    def top_users(self, n=5):
        users = [entry['user'] for entry in self.logs if entry.get('user')]
        counter = Counter(users)
        return counter.most_common(n)

    def top_urls(self, n=5):
        urls = [entry['url'] for entry in self.logs if entry.get('url')]
        counter = Counter(urls)
        return counter.most_common(n)
