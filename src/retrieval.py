"""
Project Darkroom - Week 2
Reusable retrieval module. Given a raw alert, embeds it and queries both
ChromaDB collections (ATT&CK techniques, CVE records), returning a clean
structured result that downstream code (prompt builder, FastAPI endpoint)
can consume directly.

Usage:
    from retrieval import KnowledgeRetriever

    retriever = KnowledgeRetriever()
    result = retriever.retrieve("suspicious PowerShell execution on HOST-42")
    # result["attack_matches"], result["cve_matches"]
"""

from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_DIR = Path("data/knowledge_base/chroma_db")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

DEFAULT_TOP_K_ATTACK = 3
DEFAULT_TOP_K_CVE = 3


class KnowledgeRetriever:
    """Wraps the embedding model + both ChromaDB collections behind one
    simple interface. Loads the model once on init, reused for every query -
    avoids the cost of reloading it per alert."""

    def __init__(self, chroma_dir: Path = CHROMA_DIR, model_name: str = EMBEDDING_MODEL):
        if not chroma_dir.exists():
            raise FileNotFoundError(
                f"ChromaDB directory not found at {chroma_dir}. "
                f"Run build_knowledge_base.py first."
            )

        self.model = SentenceTransformer(model_name)
        self.client = chromadb.PersistentClient(path=str(chroma_dir))

        try:
            self.attack_collection = self.client.get_collection("attack_techniques")
            self.cve_collection = self.client.get_collection("cve_records")
        except Exception as e:
            raise RuntimeError(
                "Could not load ChromaDB collections - has build_knowledge_base.py "
                "been run successfully?"
            ) from e

    def retrieve(
        self,
        alert_text: str,
        top_k_attack: int = DEFAULT_TOP_K_ATTACK,
        top_k_cve: int = DEFAULT_TOP_K_CVE,
    ) -> dict:
        """Embed the alert once, query both collections, return structured results."""
        query_embedding = self.model.encode([alert_text])[0].tolist()

        attack_raw = self.attack_collection.query(
            query_embeddings=[query_embedding], n_results=top_k_attack
        )
        cve_raw = self.cve_collection.query(
            query_embeddings=[query_embedding], n_results=top_k_cve
        )

        attack_matches = self._format_attack_results(attack_raw)
        cve_matches = self._format_cve_results(cve_raw)

        return {
            "alert_text": alert_text,
            "attack_matches": attack_matches,
            "cve_matches": cve_matches,
        }

    @staticmethod
    def _format_attack_results(raw: dict) -> list[dict]:
        if not raw["ids"] or not raw["ids"][0]:
            return []

        formatted = []
        for i in range(len(raw["ids"][0])):
            meta = raw["metadatas"][0][i]
            formatted.append({
                "technique_id": meta["technique_id"],
                "name": meta["name"],
                "tactics": meta["tactics"],
                "description": raw["documents"][0][i],
                "distance": round(raw["distances"][0][i], 4),
            })
        return formatted

    @staticmethod
    def _format_cve_results(raw: dict) -> list[dict]:
        if not raw["ids"] or not raw["ids"][0]:
            return []

        formatted = []
        for i in range(len(raw["ids"][0])):
            meta = raw["metadatas"][0][i]
            formatted.append({
                "cve_id": meta["cve_id"],
                "severity": meta["severity"],
                "cvss_score": meta["cvss_score"] if meta["cvss_score"] != -1.0 else None,
                "published": meta["published"],
                "description": raw["documents"][0][i],
                "distance": round(raw["distances"][0][i], 4),
            })
        return formatted


def _pretty_print(result: dict):
    """Quick console formatter for manual testing."""
    print(f'\nAlert: "{result["alert_text"]}"')

    print("\n  ATT&CK matches:")
    if not result["attack_matches"]:
        print("    (none)")
    for m in result["attack_matches"]:
        print(f"    {m['technique_id']} - {m['name']} "
              f"[{m['tactics']}] (distance: {m['distance']})")

    print("\n  CVE matches:")
    if not result["cve_matches"]:
        print("    (none)")
    for m in result["cve_matches"]:
        score = m["cvss_score"] if m["cvss_score"] is not None else "n/a"
        print(f"    {m['cve_id']} - {m['severity']} (CVSS {score}) "
              f"(distance: {m['distance']})")


if __name__ == "__main__":
    print("Loading retriever...")
    retriever = KnowledgeRetriever()

    test_alerts = [
        "suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM",
        "multiple failed login attempts for user admin from unfamiliar IP, 02:07 AM",
        "TCP flow observed, duration 9.6ms, 51 packets forward / 50 packets backward. "
        "High throughput: 11.8 MB/s.",
    ]

    for alert in test_alerts:
        result = retriever.retrieve(alert)
        _pretty_print(result)
        print("\n" + "-" * 70)