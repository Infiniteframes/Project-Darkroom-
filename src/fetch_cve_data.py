"""
Project Darkroom - Week 1
Fetches recent, high-severity CVE records from the NVD API and extracts
clean records for use in the RAG knowledge base.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0 (official NIST/NVD API)
License: Public domain (NIST). CVE identifiers maintained by MITRE, also
         freely redistributable with attribution.
         See ATTRIBUTION.txt written alongside the raw data.

Note: Uses an NVD API key from .env if present, for a higher rate limit.
      Falls back to the unauthenticated rate limit if no key is found.
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ---- Config ----
TARGET_COUNT = 500          # how many CVEs we want in total
RESULTS_PER_PAGE = 100       # NVD max recommended page size
YEARS_BACK = 3                # only pull CVEs published within this window
SEVERITIES = ["HIGH", "CRITICAL"]
# With an API key, NVD allows ~5-10 req/sec; without one, ~1.5 req/sec.
REQUEST_DELAY_SECONDS = 0.7 if NVD_API_KEY else 1.5
MAX_RETRIES = 3                # retry a request this many times before giving up on a window
RETRY_BACKOFF_SECONDS = 5      # wait time increases by this much each retry

# ---- Paths ----
RAW_DIR = Path("data/raw/CVE")
PROCESSED_DIR = Path("data/processed/CVE")
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

RAW_FILE = RAW_DIR / "nvd_cve_raw.json"
PROCESSED_FILE = PROCESSED_DIR / "cve_records.json"

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def daterange_chunks(start, end, chunk_days=120):
    """Yield (chunk_start, chunk_end) tuples, each spanning at most chunk_days.
    NVD rejects any single request spanning more than 120 days."""
    current = start
    while current < end:
        chunk_end = min(current + timedelta(days=chunk_days), end)
        yield current, chunk_end
        current = chunk_end


def fetch_cves():
    """Pull recent HIGH/CRITICAL CVEs from NVD, chunking the date range into
    120-day windows (NVD's hard limit) and paginating within each window."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=365 * YEARS_BACK)

    all_vulns = []

    for severity in SEVERITIES:
        if len(all_vulns) >= TARGET_COUNT:
            break

        print(f"\nFetching {severity} severity CVEs...")

        # Walk backwards from most recent window to oldest, so we get the
        # newest CVEs first and can stop early once we hit TARGET_COUNT
        chunks = list(daterange_chunks(start_date, end_date))
        chunks.reverse()

        for chunk_start, chunk_end in chunks:
            if len(all_vulns) >= TARGET_COUNT:
                break

            start_index = 0
            while True:
                params = {
                    "cvssV3Severity": severity,
                    "pubStartDate": chunk_start.strftime("%Y-%m-%dT00:00:00.000"),
                    "pubEndDate": chunk_end.strftime("%Y-%m-%dT23:59:59.999"),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }

                response = None
                headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
                for attempt in range(MAX_RETRIES):
                    try:
                        response = requests.get(BASE_URL, params=params, headers=headers, timeout=60)
                        break
                    except requests.exceptions.RequestException as e:
                        wait = RETRY_BACKOFF_SECONDS * (attempt + 1)
                        print(f"  Network error ({e.__class__.__name__}), "
                              f"retrying in {wait}s (attempt {attempt + 1}/{MAX_RETRIES})...")
                        time.sleep(wait)

                if response is None:
                    print(f"  Giving up on window {chunk_start.date()} to {chunk_end.date()} "
                          f"after {MAX_RETRIES} failed attempts, skipping.")
                    break

                if response.status_code != 200:
                    print(f"  Request failed (status {response.status_code}) for window "
                          f"{chunk_start.date()} to {chunk_end.date()}, skipping window.")
                    break

                data = response.json()
                batch = data.get("vulnerabilities", [])

                if not batch:
                    break

                all_vulns.extend(batch)
                print(f"  [{chunk_start.date()} to {chunk_end.date()}] "
                      f"+{len(batch)} records (running total: {len(all_vulns)})")

                start_index += RESULTS_PER_PAGE
                time.sleep(REQUEST_DELAY_SECONDS)

                if start_index >= data.get("totalResults", 0):
                    break
                if len(all_vulns) >= TARGET_COUNT:
                    break

    # Save raw response objects
    with open(RAW_FILE, "w", encoding="utf-8") as f:
        json.dump(all_vulns, f, indent=2)

    print(f"\nSaved {len(all_vulns)} raw CVE records -> {RAW_FILE}")
    return all_vulns


def extract_records(raw_vulns):
    """Filter raw NVD entries down to clean, usable records."""
    records = []

    for item in raw_vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # English description only
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "").strip()
                break

        if not description:
            continue

        # Prefer CVSS v3.1, fall back to v3.0, then v2 if that's all that's available
        metrics = cve.get("metrics", {})
        base_score = None
        base_severity = None

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                base_severity = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break

        records.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": base_score,
            "severity": base_severity,
            "published": cve.get("published", ""),
        })

    # Sort newest first
    records.sort(key=lambda r: r["published"], reverse=True)

    with open(PROCESSED_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print(f"Extracted {len(records)} clean CVE records -> {PROCESSED_FILE}")

    if records:
        print("\nSample record:")
        print(json.dumps(records[0], indent=2)[:500])


def write_attribution():
    attribution_text = (
        "This directory contains data sourced from the National Vulnerability Database (NVD).\n\n"
        "NVD data is a public domain product of the U.S. National Institute of Standards\n"
        "and Technology (NIST). Acknowledgment of the NVD is appreciated.\n\n"
        "CVE(R) identifiers are maintained by The MITRE Corporation and are freely\n"
        "redistributable under MITRE's CVE Usage terms.\n\n"
        "This product uses the NVD API but is not endorsed or certified by the NVD.\n\n"
        "Sources:\n"
        "  https://nvd.nist.gov/\n"
        "  https://nvd.nist.gov/developers/terms-of-use\n"
        "  https://www.cve.org/\n"
    )
    with open(RAW_DIR / "ATTRIBUTION.txt", "w", encoding="utf-8") as f:
        f.write(attribution_text)


if __name__ == "__main__":
    if NVD_API_KEY:
        print("Using NVD API key (higher rate limit).")
    else:
        print("No NVD API key found in .env - using unauthenticated rate limit.")

    raw_vulns = fetch_cves()
    extract_records(raw_vulns)
    write_attribution()
    print("\nDone. Attribution notice written to data/raw/CVE/ATTRIBUTION.txt")