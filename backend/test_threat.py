from database import save_threat

save_threat(
    ip="185.220.101.1",
    url="http://malicious-example.com",
    severity="High",
    threat_type="Phishing"
)