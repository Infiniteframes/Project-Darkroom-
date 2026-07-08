"""
Project Darkroom - Week 2
Embeds the ATT&CK technique knowledge base and CVE records into two
SEPARATE ChromaDB collections, using sentence-transformers for embeddings.

Two collections instead of one shared collection because ATT&CK and CVE
text are structurally different (general behaviors vs. specific software
vulnerabilities) - mixing them in one vector space causes cross-contamination
in retrieval results.

Everything runs locally - no API calls, zero cost.
"""

import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

ATTACK_FILE = Path("data/processed/MITRE_ATTACK/attack_techniques.json")
CVE_FILE = Path("data/processed/CVE/cve_records.json")

CHROMA_DIR = Path("data/knowledge_base/chroma_db")
CHROMA_DIR.mkdir(parents=True, exist_ok=True)

EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # small, fast, fully local


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def embed_attack_techniques(client, model):
    """Embed ATT&CK techniques into their own collection, with technique
    metadata (ID, name, tactics) attached to each entry."""
    techniques = load_json(ATTACK_FILE)
    print(f"Embedding {len(techniques)} ATT&CK techniques...")

    collection = client.get_or_create_collection(
        name="attack_techniques",
        metadata={"description": "MITRE ATT&CK technique descriptions"},
    )

    if collection.count() >= len(techniques):
        print(f"  Collection already has {collection.count()} entries, skipping.")
        return collection

    documents = [f"{t['name']}. {t['description']}" for t in techniques]
    ids = [t["technique_id"] for t in techniques]

    metadatas = []
    for t in techniques:
        metadatas.append({
            "technique_id": t["technique_id"],
            "name": t["name"],
            "tactics": ", ".join(t.get("tactics", [])) or "unknown",
        })

    embeddings = model.encode(documents, show_progress_bar=True, batch_size=64)

    seen = set()
    final_ids, final_docs, final_meta, final_emb = [], [], [], []
    for i, tid in enumerate(ids):
        if tid in seen:
            continue
        seen.add(tid)
        final_ids.append(tid)
        final_docs.append(documents[i])
        final_meta.append(metadatas[i])
        final_emb.append(embeddings[i].tolist())

    collection.add(
        ids=final_ids,
        documents=final_docs,
        metadatas=final_meta,
        embeddings=final_emb,
    )

    print(f"  Added {len(final_ids)} techniques to 'attack_techniques' collection.")
    return collection


def embed_cve_records(client, model):
    """Embed CVE records into their own collection, with severity/score
    metadata attached to each entry."""
    cves = load_json(CVE_FILE)
    print(f"\nEmbedding {len(cves)} CVE records...")

    collection = client.get_or_create_collection(
        name="cve_records",
        metadata={"description": "NVD CVE vulnerability descriptions"},
    )

    if collection.count() >= len(cves):
        print(f"  Collection already has {collection.count()} entries, skipping.")
        return collection

    documents = [c["description"] for c in cves]
    ids = [c["cve_id"] for c in cves]

    metadatas = []
    for c in cves:
        metadatas.append({
            "cve_id": c["cve_id"],
            "severity": c.get("severity") or "unknown",
            "cvss_score": c.get("cvss_score") if c.get("cvss_score") is not None else -1.0,
            "published": c.get("published", ""),
        })

    embeddings = model.encode(documents, show_progress_bar=True, batch_size=64)

    seen = set()
    final_ids, final_docs, final_meta, final_emb = [], [], [], []
    for i, cid in enumerate(ids):
        if cid in seen:
            continue
        seen.add(cid)
        final_ids.append(cid)
        final_docs.append(documents[i])
        final_meta.append(metadatas[i])
        final_emb.append(embeddings[i].tolist())

    collection.add(
        ids=final_ids,
        documents=final_docs,
        metadatas=final_meta,
        embeddings=final_emb,
    )

    print(f"  Added {len(final_ids)} CVEs to 'cve_records' collection.")
    return collection


def sanity_check_query(model, attack_collection, cve_collection):
    """Run one test query through both collections to confirm retrieval works."""
    test_alert = "suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM"
    print(f"\n--- Sanity check query ---\nAlert: \"{test_alert}\"")

    query_embedding = model.encode([test_alert])[0].tolist()

    attack_results = attack_collection.query(query_embeddings=[query_embedding], n_results=3)
    print("\nTop ATT&CK matches:")
    for tid, name, dist in zip(
        attack_results["ids"][0],
        [m["name"] for m in attack_results["metadatas"][0]],
        attack_results["distances"][0],
    ):
        print(f"  {tid} - {name} (distance: {dist:.3f})")

    cve_results = cve_collection.query(query_embeddings=[query_embedding], n_results=3)
    print("\nTop CVE matches:")
    for cid, sev, dist in zip(
        cve_results["ids"][0],
        [m["severity"] for m in cve_results["metadatas"][0]],
        cve_results["distances"][0],
    ):
        print(f"  {cid} - {sev} (distance: {dist:.3f})")


if __name__ == "__main__":
    print(f"Loading embedding model ({EMBEDDING_MODEL})...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    attack_collection = embed_attack_techniques(client, model)
    cve_collection = embed_cve_records(client, model)

    sanity_check_query(model, attack_collection, cve_collection)

    print("\nDone. ChromaDB persisted to data/knowledge_base/chroma_db/")