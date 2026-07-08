"""
Project Darkroom - Week 4 polish
Tests the triage pipeline specifically against alerts labeled "Benign" in
the CIC-IDS2017 data (i.e. genuinely normal, non-attack traffic). This is
the most important calibration check for an alert-fatigue-reduction tool:
if normal traffic gets flagged High/Critical, the system is crying wolf,
which defeats the whole point of the project.

Requires the FastAPI backend to be running (python -m uvicorn main:app
--reload --app-dir src) since this hits the real /triage endpoint.
"""

import json
import random
from collections import Counter
from pathlib import Path

import requests

CICIDS_FILE = Path("data/processed/CIC-IDS2017/alerts.json")
API_URL = "http://127.0.0.1:8000/triage"

SAMPLE_SIZE = 25
RANDOM_SEED = 7


def main():
    with open(CICIDS_FILE, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    benign_alerts = [a for a in alerts if a.get("label") == "Benign"]
    print(f"Found {len(benign_alerts)} Benign-labeled alerts in the dataset.")

    random.seed(RANDOM_SEED)
    sample = random.sample(benign_alerts, min(SAMPLE_SIZE, len(benign_alerts)))

    print(f"Testing {len(sample)} of them against the live triage API...\n")

    severities = Counter()
    results = []

    for i, alert in enumerate(sample, 1):
        alert_text = alert["alert_text"]
        try:
            resp = requests.post(API_URL, json={"alert_text": alert_text}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            severity = data["severity"]
        except requests.exceptions.RequestException as e:
            severity = "ERROR"
            print(f"  [{i}/{len(sample)}] Request failed: {e}")
            continue

        severities[severity] += 1
        results.append({"alert_text": alert_text, "severity": severity})
        print(f"  [{i}/{len(sample)}] {severity:8s} - {alert_text[:70]}")

    print("\n" + "=" * 60)
    print("SEVERITY DISTRIBUTION FOR GENUINELY BENIGN TRAFFIC")
    print("=" * 60)
    total = sum(severities.values())
    for sev in ["Low", "Medium", "High", "Critical", "ERROR"]:
        count = severities.get(sev, 0)
        if count:
            pct = count / total * 100
            print(f"  {sev:10s}: {count}/{total} ({pct:.1f}%)")

    high_critical = severities.get("High", 0) + severities.get("Critical", 0)
    print(f"\nHigh/Critical on BENIGN traffic: {high_critical}/{total} "
          f"({high_critical / total * 100:.1f}%)")
    print("(Ideally this should be low - benign traffic shouldn't alarm.)")
    print("=" * 60)


if __name__ == "__main__":
    main()