import json

with open("data/processed/CIC-IDS2017/alerts.json") as f:
    alerts = json.load(f)

for label in ["Portscan", "DDoS", "Bruteforce", "DoS", "Botnet"]:
    matches = [a for a in alerts if a["label"] == label][:3]
    print(f"\n--- {label} ---")
    for a in matches:
        print(f"[{a['alert_id']}] technique={a['suspected_technique']}")
        print(f"  {a['alert_text']}")