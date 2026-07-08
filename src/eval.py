"""
Project Darkroom - Week 3
Evaluation script. Runs every synthetic alert (known ground-truth technique)
through the full retrieve -> generate -> validate pipeline, and measures:

1. Top-1 accuracy: did the model's final technique_id match the ground truth?
2. Retrieval recall@3: was the ground-truth technique even among the top 3
   retrieved matches? (separates retrieval quality from the LLM's final
   choice - if recall@3 is high but top-1 accuracy is lower, the problem is
   in generation/prompting, not retrieval)
3. Failure rate and average retries needed

This is the "how do you know it works" evidence for the case study.
"""

import json
import time
from collections import defaultdict
from pathlib import Path

from retrieval import KnowledgeRetriever
from triage import triage_alert

SYNTHETIC_FILE = Path("data/processed/Synthetic/synthetic_alerts.json")
EVAL_OUTPUT_DIR = Path("data/processed/Eval")
EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
EVAL_RESULTS_FILE = EVAL_OUTPUT_DIR / "eval_results.json"

# Set to a smaller number (e.g. 20) for a quick test run before committing to
# the full ~140 alerts, which will take a while since each one hits the LLM.
EVAL_SAMPLE_SIZE = None  # None = use all synthetic alerts


def load_synthetic_alerts():
    with open(SYNTHETIC_FILE, "r", encoding="utf-8") as f:
        alerts = json.load(f)
    if EVAL_SAMPLE_SIZE:
        alerts = alerts[:EVAL_SAMPLE_SIZE]
    return alerts


def parent_technique(technique_id: str) -> str:
    """Strip a sub-technique suffix, e.g. 'T1059.001' -> 'T1059'.
    Used for a secondary, more forgiving accuracy metric: predicting a more
    specific child technique than the ground-truth parent is not really
    'wrong' - it can be a more precise answer than the label itself."""
    return technique_id.split(".")[0]


def run_evaluation():
    alerts = load_synthetic_alerts()
    print(f"Loading retriever...")
    retriever = KnowledgeRetriever()

    print(f"Running evaluation on {len(alerts)} synthetic alerts...")
    print("(this hits the local LLM once per alert - expect several seconds each)\n")

    results = []
    start_time = time.time()

    for i, alert in enumerate(alerts, 1):
        ground_truth_id = alert["technique_id"]
        alert_text = alert["alert_text"]

        triage_result = triage_alert(alert_text, retriever)

        predicted_id = triage_result["technique_id"]
        top1_correct = predicted_id == ground_truth_id
        parent_correct = (
            predicted_id != "unknown"
            and parent_technique(predicted_id) == parent_technique(ground_truth_id)
        )

        retrieved_ids = [m["technique_id"] for m in triage_result["retrieved_context"]["attack_matches"]]
        recall_at_3 = ground_truth_id in retrieved_ids
        recall_at_3_parent = any(
            parent_technique(rid) == parent_technique(ground_truth_id) for rid in retrieved_ids
        )

        result_row = {
            "alert_id": alert["alert_id"],
            "category": alert["category"],
            "ground_truth_technique": ground_truth_id,
            "predicted_technique": predicted_id,
            "top1_correct": top1_correct,
            "parent_correct": parent_correct,
            "recall_at_3": recall_at_3,
            "recall_at_3_parent": recall_at_3_parent,
            "retrieved_technique_ids": retrieved_ids,
            "severity": triage_result["severity"],
            "attempts_needed": triage_result["attempts_needed"],
            "failed": triage_result.get("failed", False),
        }
        results.append(result_row)

        if top1_correct:
            status = "OK  "
        elif parent_correct:
            status = "PAR "
        elif recall_at_3:
            status = "~R3 "
        else:
            status = "MISS"
        print(f"  [{i}/{len(alerts)}] {alert['alert_id']} ({alert['category']}): "
              f"{status} - predicted {predicted_id}, truth {ground_truth_id}")

    elapsed = time.time() - start_time

    with open(EVAL_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print_summary(results, elapsed)
    return results


def print_summary(results: list[dict], elapsed_seconds: float):
    total = len(results)
    top1_correct = sum(1 for r in results if r["top1_correct"])
    parent_correct = sum(1 for r in results if r["parent_correct"])
    recall_at_3 = sum(1 for r in results if r["recall_at_3"])
    recall_at_3_parent = sum(1 for r in results if r["recall_at_3_parent"])
    failed = sum(1 for r in results if r["failed"])
    avg_attempts = sum(r["attempts_needed"] for r in results) / total if total else 0

    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Total alerts evaluated: {total}")
    print(f"Time taken: {elapsed_seconds / 60:.1f} minutes "
          f"({elapsed_seconds / total:.1f}s per alert avg)")
    print()
    print(f"Top-1 exact match: {top1_correct}/{total} ({top1_correct / total * 100:.1f}%)")
    print(f"Top-1 same-family match (parent technique correct, "
          f"e.g. predicted T1059.001 vs ground truth T1059): "
          f"{parent_correct}/{total} ({parent_correct / total * 100:.1f}%)")
    print(f"Recall@3 exact: {recall_at_3}/{total} ({recall_at_3 / total * 100:.1f}%)")
    print(f"Recall@3 same-family: {recall_at_3_parent}/{total} "
          f"({recall_at_3_parent / total * 100:.1f}%)")
    print(f"Pipeline failures (exhausted retries): {failed}/{total} "
          f"({failed / total * 100:.1f}%)")
    print(f"Average attempts needed: {avg_attempts:.2f}")

    by_category = defaultdict(lambda: {
        "total": 0, "correct": 0, "parent_correct": 0,
        "recall3": 0, "recall3_parent": 0,
    })
    for r in results:
        by_category[r["category"]]["total"] += 1
        if r["top1_correct"]:
            by_category[r["category"]]["correct"] += 1
        if r["parent_correct"]:
            by_category[r["category"]]["parent_correct"] += 1
        if r["recall_at_3"]:
            by_category[r["category"]]["recall3"] += 1
        if r["recall_at_3_parent"]:
            by_category[r["category"]]["recall3_parent"] += 1

    print("\nBy category:")
    for cat, stats in sorted(by_category.items()):
        t = stats["total"]
        print(f"  {cat} (n={t}):")
        print(f"    top-1 exact: {stats['correct']}/{t} ({stats['correct']/t*100:.1f}%)  |  "
              f"top-1 same-family: {stats['parent_correct']}/{t} ({stats['parent_correct']/t*100:.1f}%)")
        print(f"    recall@3 exact: {stats['recall3']}/{t} ({stats['recall3']/t*100:.1f}%)  |  "
              f"recall@3 same-family: {stats['recall3_parent']}/{t} ({stats['recall3_parent']/t*100:.1f}%)")

    print(f"\nFull results saved to: {EVAL_RESULTS_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    run_evaluation()