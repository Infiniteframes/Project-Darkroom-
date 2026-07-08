"""
Project Darkroom - Week 3
FastAPI wrapper around the triage pipeline. Loads the retriever once at
startup (expensive - embedding model + ChromaDB), reuses it across every
request rather than reloading per call.

Run with:
    python -m uvicorn main:app --reload --app-dir src

Then visit http://127.0.0.1:8000/docs for interactive API docs (FastAPI
generates this automatically).
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from retrieval import KnowledgeRetriever
from triage import triage_alert

# Loaded once at startup, reused across all requests - avoids reloading the
# embedding model and reconnecting to ChromaDB on every single alert.
retriever: KnowledgeRetriever | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global retriever
    print("Loading knowledge retriever (embedding model + ChromaDB)...")
    retriever = KnowledgeRetriever()
    print("Retriever ready.")
    yield
    # Nothing to clean up on shutdown - ChromaDB persists to disk automatically


app = FastAPI(
    title="Project Darkroom",
    description="AI-powered security alert triage assistant, grounded in "
                "MITRE ATT&CK and CVE data via local RAG.",
    version="0.1.0",
    lifespan=lifespan,
)

# Allows the React dev server (Vite defaults to localhost:5173) to call this
# API from the browser. Restricted to localhost origins - this is a local
# demo project, not a publicly deployed service.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://192.168.0.151:5173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AlertRequest(BaseModel):
    alert_text: str = Field(
        ...,
        min_length=1,
        description="The raw security alert text to triage",
        examples=["suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM"],
    )


class TriageResponse(BaseModel):
    summary: str
    technique_id: str
    severity: str
    recommended_action: str
    attempts_needed: int
    failed: bool = False
    retrieved_context: dict


@app.get("/health")
def health():
    """Quick check that the API is up and the retriever has loaded."""
    return {
        "status": "ok",
        "retriever_loaded": retriever is not None,
    }


@app.post("/triage", response_model=TriageResponse)
def triage(request: AlertRequest):
    """Takes a raw alert, runs the full retrieve -> generate -> validate
    pipeline, returns a structured triage assessment."""
    if retriever is None:
        raise HTTPException(
            status_code=503,
            detail="Retriever not ready yet - server may still be starting up.",
        )

    alert_text = request.alert_text.strip()
    if not alert_text:
        raise HTTPException(status_code=400, detail="alert_text cannot be empty")

    result = triage_alert(alert_text, retriever)
    return result