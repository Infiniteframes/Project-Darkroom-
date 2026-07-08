"""
Project Darkroom - Week 2
The core triage pipeline: takes a raw alert, retrieves relevant ATT&CK/CVE
context, builds a prompt, and asks the local LLM to produce a structured
triage assessment (summary, technique, severity, recommended action).

This is the "generation" half of RAG - retrieval.py handles the "retrieval" half.
"""

import json
import re
import time

import ollama

from retrieval import KnowledgeRetriever

MODEL_NAME = "llama3.1:8b"
MAX_RETRIES = 3
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}

# Retrieval always returns the top-N nearest matches even when nothing is
# genuinely relevant (nearest-neighbor search has no built-in "reject"
# option). Based on distances observed during Week 2/3 testing, matches
# with distance below ~1.15 were consistently accurate (e.g. PowerShell
# alert -> T1059.001 at 1.077); distances above ~1.2 tended to be weak,
# coincidental matches rather than genuine technique matches.
WEAK_MATCH_DISTANCE_THRESHOLD = 1.15

PROMPT_TEMPLATE = """You are a SOC (Security Operations Center) analyst assistant. \
Given a raw security alert and related context retrieved from a knowledge base, \
produce a triage assessment.

Alert: {alert_text}

Related ATT&CK techniques (ranked by relevance):
{attack_matches}

Related CVEs (ranked by relevance):
{cve_matches}

Important: retrieval always returns the closest available matches, even when \
nothing genuinely relevant exists in the knowledge base. A large amount of \
real-world traffic is routine and not malicious - low packet counts, short \
unremarkable flows, and ordinary logins are common and expected. Do not treat \
the mere presence of retrieved technique names as evidence of a real threat. \
Only raise severity when the alert itself contains a genuine indicator of \
concern (e.g. unusual timing, credential abuse, scanning behavior, clearly \
malicious patterns). "Low" severity is a normal, expected, and frequent \
outcome for ordinary activity - use it whenever nothing in the alert itself \
is actually concerning, even if some technique names were retrieved.

Based on the alert and the context above, respond with ONLY a JSON object, \
no other text, no markdown formatting, no explanation. The object must have \
exactly these fields:
- "summary": a 2-3 sentence plain-English explanation of what likely happened \
and why it matters, written for a SOC analyst
- "technique_id": the single most relevant ATT&CK technique ID from the list \
above (or "unknown" if none genuinely apply)
- "severity": one of "Low", "Medium", "High", "Critical"
- "recommended_action": one concrete next step the analyst should take

Respond with the JSON object now:"""


def format_attack_matches(matches: list[dict]) -> str:
    if not matches:
        return "(no relevant techniques found)"

    # If even the best match is a weak one, tell the model explicitly rather
    # than silently handing it technique names that look like evidence.
    best_distance = min(m["distance"] for m in matches)
    if best_distance > WEAK_MATCH_DISTANCE_THRESHOLD:
        lines = [
            f"(No strong technique match found - best match distance "
            f"{best_distance:.2f} is above the confidence threshold. "
            f"This alert likely does NOT represent a known attack technique. "
            f"The closest, still-weak candidates were:)"
        ]
    else:
        lines = []

    for m in matches:
        desc = m["description"][:200].rsplit(" ", 1)[0] + "..."
        lines.append(f"- {m['technique_id']} ({m['name']}, distance {m['distance']:.2f}): {desc}")
    return "\n".join(lines)


def format_cve_matches(matches: list[dict]) -> str:
    if not matches:
        return "(no relevant CVEs found)"
    lines = []
    for m in matches:
        desc = m["description"][:200].rsplit(" ", 1)[0] + "..."
        score = m["cvss_score"] if m["cvss_score"] is not None else "n/a"
        lines.append(f"- {m['cve_id']} (severity: {m['severity']}, CVSS: {score}): {desc}")
    return "\n".join(lines)


def build_prompt(retrieval_result: dict) -> str:
    return PROMPT_TEMPLATE.format(
        alert_text=retrieval_result["alert_text"],
        attack_matches=format_attack_matches(retrieval_result["attack_matches"]),
        cve_matches=format_cve_matches(retrieval_result["cve_matches"]),
    )


def extract_json_object(text: str) -> dict:
    """Same defensive parsing pattern used in generate_synthetic_alerts.py -
    local models sometimes wrap JSON in markdown fences or add stray text."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")

    return json.loads(text[start:end + 1])


def validate_triage(data: dict, retrieval_result: dict) -> dict | None:
    """Check the parsed JSON has the fields we need, with sane values.
    Returns a cleaned dict, or None if validation fails."""
    required = {"summary", "technique_id", "severity", "recommended_action"}
    if not required.issubset(data.keys()):
        return None

    severity = data["severity"]
    if severity not in VALID_SEVERITIES:
        return None

    summary = str(data["summary"]).strip()
    action = str(data["recommended_action"]).strip()
    if not summary or not action:
        return None

    # technique_id should either be "unknown" or one of the IDs we actually
    # retrieved - guards against the model inventing a plausible-looking but
    # wrong technique ID that wasn't in the retrieved context
    retrieved_ids = {m["technique_id"] for m in retrieval_result["attack_matches"]}
    technique_id = str(data["technique_id"]).strip()
    if technique_id != "unknown" and technique_id not in retrieved_ids:
        return None

    return {
        "summary": summary,
        "technique_id": technique_id,
        "severity": severity,
        "recommended_action": action,
    }


def triage_alert(alert_text: str, retriever: KnowledgeRetriever) -> dict:
    """Full pipeline: retrieve context, build prompt, generate, validate,
    retry on failure. Returns the final structured result, including the
    retrieved context for transparency/debugging."""
    retrieval_result = retriever.retrieve(alert_text)
    prompt = build_prompt(retrieval_result)

    for attempt in range(MAX_RETRIES):
        response = ollama.generate(model=MODEL_NAME, prompt=prompt)
        raw_text = response["response"]

        try:
            parsed = extract_json_object(raw_text)
            cleaned = validate_triage(parsed, retrieval_result)
            if cleaned:
                cleaned["retrieved_context"] = {
                    "attack_matches": retrieval_result["attack_matches"],
                    "cve_matches": retrieval_result["cve_matches"],
                }
                cleaned["attempts_needed"] = attempt + 1
                return cleaned

            print(f"    Attempt {attempt + 1}: validation failed, retrying...")

        except (json.JSONDecodeError, ValueError) as e:
            print(f"    Attempt {attempt + 1}: failed to parse JSON ({e}), retrying...")

        time.sleep(1)

    # All retries exhausted - return a clearly-marked failure rather than
    # silently returning nothing
    return {
        "summary": "Triage failed - model did not return valid output after retries.",
        "technique_id": "unknown",
        "severity": "Medium",  # fail safe toward caution, not toward "Low"
        "recommended_action": "Manual review required - automated triage failed.",
        "retrieved_context": {
            "attack_matches": retrieval_result["attack_matches"],
            "cve_matches": retrieval_result["cve_matches"],
        },
        "attempts_needed": MAX_RETRIES,
        "failed": True,
    }


def _pretty_print(alert_text: str, result: dict):
    print(f'\nAlert: "{alert_text}"')
    print(f"  Technique: {result['technique_id']}")
    print(f"  Severity: {result['severity']}")
    print(f"  Summary: {result['summary']}")
    print(f"  Action: {result['recommended_action']}")
    print(f"  (resolved in {result['attempts_needed']} attempt(s))")


if __name__ == "__main__":
    print("Loading retriever and model...")
    retriever = KnowledgeRetriever()

    test_alerts = [
        "suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM",
        "multiple failed login attempts for user admin from unfamiliar IP, 02:07 AM",
        "TCP flow observed, duration 9.6ms, 51 packets forward / 50 packets backward. "
        "High throughput: 11.8 MB/s.",
    ]

    for alert in test_alerts:
        result = triage_alert(alert, retriever)
        _pretty_print(alert, result)
        print("-" * 70)