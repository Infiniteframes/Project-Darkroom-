"""
Project Darkroom - Week 1
Downloads MITRE ATT&CK Enterprise data and extracts clean technique records
for use in the RAG knowledge base.

Source: https://github.com/mitre/cti (official MITRE repository)
License: MITRE ATT&CK is free to use for research/commercial purposes.
         Attribution required - see data/raw/MITRE_ATTACK/ATTRIBUTION.txt
"""

import json
import requests
from pathlib import Path

# ---- Paths ----
RAW_DIR = Path("data/raw/MITRE_ATTACK")
PROCESSED_DIR = Path("data/processed/MITRE_ATTACK")
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

RAW_FILE = RAW_DIR / "enterprise-attack.json"
PROCESSED_FILE = PROCESSED_DIR / "attack_techniques.json"

SOURCE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def download_raw_data():
    """Download the raw ATT&CK STIX JSON if not already present."""
    if RAW_FILE.exists():
        print(f"Raw file already exists at {RAW_FILE}, skipping download.")
        return

    print("Downloading MITRE ATT&CK Enterprise data...")
    response = requests.get(SOURCE_URL, timeout=60)
    response.raise_for_status()

    with open(RAW_FILE, "w", encoding="utf-8") as f:
        f.write(response.text)

    print(f"Saved raw data to {RAW_FILE} ({len(response.text) / 1_000_000:.1f} MB)")


def extract_techniques():
    """Filter the raw STIX objects down to clean, usable technique records."""
    print("Loading raw data...")
    with open(RAW_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = []

    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        # Skip revoked or deprecated techniques - no longer valid
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Pull the official technique ID (e.g. T1059 or T1055.011)
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue  # skip anything without a proper ATT&CK ID

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "").strip(),
            "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])],
            "platforms": obj.get("x_mitre_platforms", []),
        })

    # Sort by technique ID for readability
    techniques.sort(key=lambda t: t["technique_id"])

    with open(PROCESSED_FILE, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)

    print(f"Extracted {len(techniques)} techniques -> {PROCESSED_FILE}")

    # Quick sanity check - show one example
    print("\nSample record:")
    print(json.dumps(techniques[0], indent=2)[:500])


def write_attribution():
    """Write the required MITRE attribution notice alongside the raw data."""
    attribution_text = (
        "This directory contains data derived from MITRE ATT&CK.\n\n"
        "(c) 2026 The MITRE Corporation. This work is reproduced and "
        "distributed with the permission of The MITRE Corporation.\n\n"
        "Source: https://github.com/mitre/cti\n"
        "License: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/\n"
    )
    with open(RAW_DIR / "ATTRIBUTION.txt", "w", encoding="utf-8") as f:
        f.write(attribution_text)


if __name__ == "__main__":
    download_raw_data()
    extract_techniques()
    write_attribution()
    print("\nDone. Attribution notice written to data/raw/MITRE_ATTACK/ATTRIBUTION.txt")