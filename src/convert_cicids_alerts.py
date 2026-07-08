"""
Project Darkroom - Week 1
Converts sampled rows from the CIC-IDS2017 dataset into human-readable
"alert" text, similar to what a real SOC alerting tool would output.

Source: Kaggle mirror of CIC-IDS2017 (dhoogla/cicids2017)
License: Free for academic, research, and commercial use under the CIC dataset license.

Note: This "no-metadata" version has no IP/port fields - only flow-level
      statistics (protocol, duration, packet/byte counts, TCP flag counts).
      Alert text is generated from those features only.
"""

import json
import random
from pathlib import Path

import pandas as pd

EXTRACT_DIR = Path("data/raw/CIC-IDS2017/extracted")
PROCESSED_DIR = Path("data/processed/CIC-IDS2017")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = PROCESSED_DIR / "alerts.json"

ROWS_PER_FILE = 60  # ~60 rows x 8 files = ~480 alerts total
RANDOM_SEED = 42

# Rough, heuristic mapping from CIC-IDS2017 labels to MITRE ATT&CK techniques.
# These are approximate associations for demo purposes, not official MITRE
# annotations - documented as such in the case study.
LABEL_TO_TECHNIQUE = {
    "Benign": None,
    "Botnet": "T1071",       # Application Layer Protocol (C2 communication)
    "Bruteforce": "T1110",   # Brute Force
    "DDoS": "T1498",         # Network Denial of Service
    "DoS": "T1499",          # Endpoint Denial of Service
    "Infiltration": "T1190", # Exploit Public-Facing Application
    "Portscan": "T1046",     # Network Service Discovery
    "WebAttacks": "T1190",   # Exploit Public-Facing Application
}

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}


def label_from_filename(filename: str) -> str:
    """Extract the attack label from a filename like 'DDoS-Friday-no-metadata.parquet'."""
    return filename.split("-")[0]


def describe_row(row: pd.Series) -> str:
    """Turn one flow record into a plain-English alert description."""
    protocol = PROTOCOL_NAMES.get(int(row.get("Protocol", -1)), f"Protocol#{row.get('Protocol')}")
    duration_ms = row.get("Flow Duration", 0) / 1000  # microseconds -> ms
    fwd_packets = int(row.get("Total Fwd Packets", 0))
    bwd_packets = int(row.get("Total Backward Packets", 0))
    syn = int(row.get("SYN Flag Count", 0))
    ack = int(row.get("ACK Flag Count", 0))
    rst = int(row.get("RST Flag Count", 0))
    fin = int(row.get("FIN Flag Count", 0))
    bytes_per_sec = row.get("Flow Bytes/s", 0)

    parts = [
        f"{protocol} flow observed, duration {duration_ms:.1f}ms, "
        f"{fwd_packets} packets forward / {bwd_packets} packets backward."
    ]

    if syn > 0 and ack == 0:
        parts.append(f"{syn} SYN packet(s) with no corresponding ACK - "
                      f"possible incomplete handshake / scan pattern.")
    if rst > 0:
        parts.append(f"{rst} RST flag(s) observed - connection reset detected.")
    if fin > 0 and syn > 0:
        parts.append("Handshake and termination flags both present - completed session.")

    if bytes_per_sec and bytes_per_sec > 1_000_000:
        parts.append(f"High throughput: {bytes_per_sec / 1_000_000:.1f} MB/s.")

    return " ".join(parts)


def interestingness_score(row: pd.Series) -> float:
    """Rough score for how 'notable' a flow record is, so sampling favors
    rows that actually produce distinctive alert text rather than flat,
    uneventful ones."""
    score = 0.0
    syn = row.get("SYN Flag Count", 0)
    ack = row.get("ACK Flag Count", 0)
    rst = row.get("RST Flag Count", 0)
    bytes_per_sec = row.get("Flow Bytes/s", 0) or 0
    fwd = row.get("Total Fwd Packets", 0)
    bwd = row.get("Total Backward Packets", 0)

    if syn > 0 and ack == 0:
        score += 3
    if rst > 0:
        score += 2
    if bytes_per_sec > 1_000_000:
        score += 2
    if fwd > 20 or bwd > 20:
        score += 1
    if abs(fwd - bwd) > 15:  # lopsided flows are often more notable
        score += 1

    return score


def build_alerts():
    random.seed(RANDOM_SEED)
    parquet_files = sorted(EXTRACT_DIR.glob("*.parquet"))

    if not parquet_files:
        raise FileNotFoundError(f"No parquet files found in {EXTRACT_DIR}")

    all_alerts = []
    alert_id = 1

    for pf in parquet_files:
        label = label_from_filename(pf.name)
        technique = LABEL_TO_TECHNIQUE.get(label)

        print(f"Sampling {pf.name} (label: {label})...")
        df = pd.read_parquet(pf)

        # For Benign traffic specifically, use PURE random sampling instead
        # of interestingness-biased sampling. "Distinctive" benign flows
        # (unusually high throughput, lopsided packets) generate alert text
        # that reads as alarming even though the ground truth is normal
        # traffic - biasing toward them was found to cause the triage
        # system to over-flag genuinely benign activity as High severity.
        if label == "Benign":
            sample = df.sample(n=min(ROWS_PER_FILE, len(df)), random_state=RANDOM_SEED)
            print(f"  -> sampled {len(sample)} rows (pure random - benign traffic "
                  f"should look typical, not statistically distinctive)")
        else:
            # Score every row for "interestingness", then take a mix:
            # 70% from the most distinctive rows, 30% purely random for variety
            # (so we're not exclusively showing dramatic traffic).
            df = df.copy()
            df["_score"] = df.apply(interestingness_score, axis=1)

            n_top = int(ROWS_PER_FILE * 0.7)
            n_random = ROWS_PER_FILE - n_top

            top_rows = df.sort_values("_score", ascending=False).head(n_top * 3)
            top_sample = top_rows.sample(n=min(n_top, len(top_rows)), random_state=RANDOM_SEED)

            remaining = df.drop(top_sample.index)
            random_sample = remaining.sample(n=min(n_random, len(remaining)), random_state=RANDOM_SEED)

            sample = pd.concat([top_sample, random_sample]).drop(columns=["_score"])
            print(f"  -> sampled {len(sample)} rows ({n_top} distinctive + {n_random} random)")

        for _, row in sample.iterrows():
            alert_text = describe_row(row)
            all_alerts.append({
                "alert_id": f"ALERT-{alert_id:04d}",
                "label": label,
                "suspected_technique": technique,
                "alert_text": alert_text,
                "source_file": pf.name,
            })
            alert_id += 1

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\nSaved {len(all_alerts)} alert records -> {OUTPUT_FILE}")
    print("\nSample alerts:")
    for a in all_alerts[:3]:
        print(f"\n  [{a['alert_id']}] label={a['label']} technique={a['suspected_technique']}")
        print(f"    {a['alert_text']}")


def write_attribution():
    attribution_text = (
        "This directory contains data derived from the CIC-IDS2017 dataset.\n\n"
        "Original dataset: Canadian Institute for Cybersecurity (CIC), University of\n"
        "New Brunswick. Free for academic, research, and commercial use under the\n"
        "CIC dataset license.\n\n"
        "Citation: Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. (2018). "
        "\"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic "
        "Characterization\", 4th International Conference on Information Systems "
        "Security and Privacy (ICISSP), Portugal.\n\n"
        "Accessed via Kaggle mirror: https://www.kaggle.com/datasets/dhoogla/cicids2017\n"
        "Original source: https://www.unb.ca/cic/datasets/ids-2017.html\n\n"
        "Note: alert_text fields and label-to-ATT&CK-technique mappings in\n"
        "alerts.json are heuristic derivations created for this project, not\n"
        "part of the original dataset or official MITRE annotations.\n"
    )
    with open(Path("data/raw/CIC-IDS2017") / "ATTRIBUTION.txt", "w", encoding="utf-8") as f:
        f.write(attribution_text)


if __name__ == "__main__":
    build_alerts()
    write_attribution()
    print("\nDone. Attribution notice written to data/raw/CIC-IDS2017/ATTRIBUTION.txt")