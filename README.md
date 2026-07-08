# Darkroom

An AI-powered security alert triage assistant. It takes a raw, noisy alert and returns a plain-English explanation, a severity score, and a next step — grounded in real MITRE ATT&CK and CVE data instead of guessed from memory.

I built this to learn RAG systems and LLM application engineering end to end: data pipeline, vector retrieval, prompt design, evaluation, and a working frontend. It runs entirely on a local model, so it costs nothing to run.

## The problem

A SOC gets thousands of alerts a day. Most are routine. Figuring out which ones actually matter takes time an analyst doesn't always have, especially a junior one who hasn't memorized hundreds of ATT&CK techniques yet.

Darkroom doesn't decide what's spam. It explains every alert fast enough that a human can make that call in seconds instead of minutes.

## How it works

1. **Retrieve** — the alert gets embedded and matched against 697 MITRE ATT&CK techniques and 307 CVEs stored in ChromaDB
2. **Reason** — a local Llama 3.1 8B model reads the alert alongside the retrieved context and writes an assessment
3. **Validate** — if the model claims a technique that wasn't actually retrieved, the answer gets rejected and it tries again
4. **Report** — a summary, severity, and one next step, served over a FastAPI endpoint

## Tech stack

**Backend:** Python, FastAPI, ChromaDB, sentence-transformers, Ollama (Llama 3.1 8B)
**Frontend:** React, TypeScript, Vite, Tailwind CSS, Framer Motion

## Results

I evaluated it against 140 synthetic alerts with known ground-truth techniques:

| Metric | Result |
|---|---|
| Top-1 exact match | 22.9% |
| Top-1 same-family match | 35.0% |
| Recall@3 (correct technique retrieved) | 30.0% |

Endpoint and identity alerts do reasonably well. Cloud alerts are the weak spot — recall@3 drops to 8.6% there, which means the correct technique often isn't even in the retrieved candidates, not just misjudged by the model once it has them. My best guess is that cloud ATT&CK descriptions are conceptually close to each other in a way a small general-purpose embedding model struggles to separate. Full breakdown is in `PROGRESS.md`.

I also found a real bug while polishing this: genuinely benign network traffic was getting flagged High or Critical 84% of the time. Two causes, both fixed — the data sampling favored statistically unusual "benign" traffic over typical traffic, and the prompt had no way for the model to say "nothing here actually matches." After the fix, that number is down to 4%.

## Running it locally

You'll need [Ollama](https://ollama.com) with `llama3.1:8b` pulled, and Node.js.

```bash
# Backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --app-dir src

# Frontend, separate terminal
cd dashboard
npm install
npm run dev
```

Then open `http://localhost:5173`.

## What I'd try next

- A bigger or security-tuned embedding model for the cloud-retrieval gap
- Running the same eval against a paid API, just to see where the local model actually stands
- Retrieving similar past alerts too, not only static ATT&CK/CVE reference data

## License

MIT
