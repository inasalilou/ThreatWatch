#!/usr/bin/env python3
import sys
import json
import requests

# Script d'integration Wazuh vers SIEM ThreatWatch (MITRE T1087)
def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]
    with open(alert_file, "r") as f:
        alert_json = json.load(f)

    # Transmission vers l'API locale ThreatWatch
    threatwatch_url = "http://192.168.56.1:8001/api/v1/siem/alerts"
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(threatwatch_url, json=alert_json, headers=headers, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"Erreur envoi ThreatWatch: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
