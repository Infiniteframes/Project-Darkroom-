"""
Project Darkroom - Week 1
Generates synthetic security alerts using the local Llama 3.1 8B model
(via Ollama), mapped to specific MITRE ATT&CK techniques. Fills the gap
left by CIC-IDS2017, which only covers network-style alerts - this adds
endpoint, cloud, and identity alert types.

Runs entirely locally via Ollama - zero API cost.
"""

import json
import re
import time
from pathlib import Path

import ollama

PROCESSED_DIR = Path("data/processed/Synthetic")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = PROCESSED_DIR / "synthetic_alerts.json"

MODEL_NAME = "llama3.1:8b"
ALERTS_PER_TECHNIQUE = 7   # ~20 techniques x 7 = ~140 alerts
MAX_RETRIES = 3

# Curated subset of ATT&CK techniques covering endpoint, cloud, and identity
# activity - the categories NOT well represented in the network-flow data.
TECHNIQUES = [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "category": "endpoint"},
    {"id": "T1059.001", "name": "PowerShell", "category": "endpoint"},
    {"id": "T1053", "name": "Scheduled Task/Job", "category": "endpoint"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "category": "endpoint"},
    {"id": "T1055", "name": "Process Injection", "category": "endpoint"},
    {"id": "T1112", "name": "Modify Registry", "category": "endpoint"},
    {"id": "T1078", "name": "Valid Accounts", "category": "identity"},
    {"id": "T1110", "name": "Brute Force", "category": "identity"},
    {"id": "T1098", "name": "Account Manipulation", "category": "identity"},
    {"id": "T1136", "name": "Create Account", "category": "identity"},
    {"id": "T1531", "name": "Account Access Removal", "category": "identity"},
    {"id": "T1621", "name": "Multi-Factor Authentication Request Generation", "category": "identity"},
    {"id": "T1552", "name": "Unsecured Credentials", "category": "identity"},
    {"id": "T1530", "name": "Data from Cloud Storage", "category": "cloud"},
    {"id": "T1078.004", "name": "Cloud Accounts", "category": "cloud"},
    {"id": "T1526", "name": "Cloud Service Discovery", "category": "cloud"},
    {"id": "T1496", "name": "Resource Hijacking", "category": "cloud"},
    {"id": "T1537", "name": "Transfer Data to Cloud Account", "category": "cloud"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "category": "endpoint"},
    {"id": "T1003", "name": "OS Credential Dumping", "category": "identity"},
]

PROMPT_TEMPLATE = """You are generating realistic, synthetic SOC (Security Operations Center) \
alert log lines for a security training dataset. All data is fictional.

Generate {n} realistic, DIFFERENT raw security alert lines for the MITRE ATT&CK \
technique: {technique_id} - {technique_name} (category: {category}).

Each alert should look like a real automated system alert, similar in style to:
"suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM"

Respond with ONLY a JSON array, no other text, no markdown formatting, no explanation.
Each item in the array must be an object with exactly these fields:
- "alert_text": the raw alert line (string, one sentence, realistic style)
- "severity": one of "Low", "Medium", "High", "Critical"

Example format:
[
  {{"alert_text": "suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM", "severity": "High"}},
  {{"alert_text": "multiple failed login attempts for user admin from unfamiliar IP, 02:07 AM", "severity": "Medium"}}
]

Now generate {n} alerts for {technique_id} - {technique_name}. JSON array only:"""


def extract_json_array(text: str):
    """Local models sometimes wrap JSON in markdown fences or add stray text.
    Try to pull out just the JSON array portion."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON array found in model output")

    return json.loads(text[start:end + 1])


def generate_for_technique(technique: dict, n: int):
    """Call the local model for one technique, with retries on malformed JSON."""
    prompt = PROMPT_TEMPLATE.format(
        n=n,
        technique_id=technique["id"],
        technique_name=technique["name"],
        category=technique["category"],
    )

    for attempt in range(MAX_RETRIES):
        try:
            response = ollama.generate(model=MODEL_NAME, prompt=prompt)
            raw_text = response["response"]
            items = extract_json_array(raw_text)

            valid_severities = {"Low", "Medium", "High", "Critical"}
            cleaned = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                alert_text = item.get("alert_text", "").strip()
                severity = item.get("severity", "Medium")
                if severity not in valid_severities:
                    severity = "Medium"
                if alert_text:
                    cleaned.append({"alert_text": alert_text, "severity": severity})

            if cleaned:
                return cleaned

            print(f"    Attempt {attempt + 1}: got empty/invalid results, retrying...")

        except (json.JSONDecodeError, ValueError) as e:
            print(f"    Attempt {attempt + 1}: failed to parse JSON ({e}), retrying...")

        time.sleep(1)

    print(f"    Giving up on {technique['id']} after {MAX_RETRIES} attempts.")
    return []


def build_synthetic_alerts():
    all_alerts = []
    alert_id = 1

    print(f"Generating synthetic alerts using {MODEL_NAME} (local, via Ollama)...\n")

    for technique in TECHNIQUES:
        print(f"[{technique['id']}] {technique['name']} ({technique['category']})...")
        results = generate_for_technique(technique, ALERTS_PER_TECHNIQUE)

        for item in results:
            all_alerts.append({
                "alert_id": f"SYN-{alert_id:04d}",
                "technique_id": technique["id"],
                "technique_name": technique["name"],
                "category": technique["category"],
                "alert_text": item["alert_text"],
                "severity": item["severity"],
                "source": "synthetic_llama",
            })
            alert_id += 1

        print(f"  -> generated {len(results)} alerts")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\nSaved {len(all_alerts)} synthetic alerts -> {OUTPUT_FILE}")
    print("\nSample alerts:")
    for a in all_alerts[:5]:
        print(f"\n  [{a['alert_id']}] {a['technique_id']} ({a['severity']})")
        print(f"    {a['alert_text']}")


def write_attribution():
    note = (
        "This directory contains synthetic security alert data generated locally\n"
        "using Meta's Llama 3.1 8B model via Ollama, for Project Darkroom.\n\n"
        "These alerts are entirely fictional, generated for demonstration and\n"
        "training purposes. They are mapped to real MITRE ATT&CK technique IDs\n"
        "but the alert text itself, hostnames, usernames, and timestamps are\n"
        "invented and do not represent real events, systems, or people.\n\n"
        "Generation cost: $0 (local inference, no API calls).\n"
    )
    with open(PROCESSED_DIR / "NOTE.txt", "w", encoding="utf-8") as f:
        f.write(note)


if __name__ == "__main__":
    build_synthetic_alerts()
    write_attribution()
    print("\nDone. Note written to data/processed/Synthetic/NOTE.txt")