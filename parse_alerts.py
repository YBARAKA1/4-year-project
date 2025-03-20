import json

def parse_suricata_alerts(self, log_file):
    """Parse Suricata alerts from eve.json."""
    alerts = []
    try:
        with open(log_file, "r") as f:
            for line in f:
                alert = json.loads(line)
                if alert["event_type"] == "alert":
                    alerts.append({
                        "timestamp": alert["timestamp"],
                        "src_ip": alert["src_ip"],
                        "dest_ip": alert["dest_ip"],
                        "signature": alert["alert"]["signature"],
                        "severity": alert["alert"]["severity"]
                    })
    except Exception as e:
        print(f"Error parsing Suricata alerts: {e}")
    return alerts