# Project Darkroom - Progress Log

A running record of what's been built, why, and where things live.
Last updated: Week 4 dashboard complete - severity calibration fixed, live
on desktop and mobile, ready for GitHub

---

## What this project is

An AI-powered security alert triage assistant. Takes a raw, noisy security
alert and returns a plain-English verdict: what likely happened, how bad it
is, and what to do next - grounded in real MITRE ATT&CK and CVE data via RAG
(retrieval-augmented generation), running entirely on a free, local LLM.

**Important note on framing:** this is not a trained ML model (no
`model.fit()`, no labeled training). It's an AI *system* built by combining
two pre-trained models - Llama 3.1 8B and all-MiniLM-L6-v2 - through
retrieval engineering, prompt design, and validation logic. The correct term
is AI engineering / LLM application development, not classic ML.

---

## Environment setup

- **Python virtual environment** (`venv/`) - isolates project dependencies
  from the rest of the machine
- **Ollama** installed locally, running **Llama 3.1 8B** - confirmed running
  on GPU (RTX 5060, 100% GPU offload, ~5.3GB VRAM used)
- **All packages** listed in `requirements.txt` - reproducible with
  `pip install -r requirements.txt`
- **Frontend**: React + TypeScript + Vite + Tailwind CSS v4 + Framer Motion,
  in `dashboard/` - its own separate Node project with its own
  `package.json`/`node_modules`

---

## WEEK 1 - Data pipeline (COMPLETE)

Goal: gather and clean all the data the system needs, from free public
sources, at zero cost.

| Source | What it is | Status | Records |
|---|---|---|---|
| MITRE ATT&CK | Catalog of known attacker techniques (e.g. T1059 = command-line abuse) | Done | 697 techniques |
| NVD CVE | Public database of known software vulnerabilities | Done | 307 records (HIGH/CRITICAL, recent) |
| CIC-IDS2017 | Real network traffic dataset, labeled attack + benign flows | Done | 480 alert-style samples across 8 categories |
| Synthetic alerts | Alerts generated locally via Llama 3.1 8B, covering endpoint/cloud/identity | Done | 140 alerts across 20 ATT&CK techniques |

**Total knowledge base + alert data: ~1,624 records**, all free/public/locally
generated, $0 total cost. Attribution notices written alongside raw data in
each source's folder.

### Week 1 files (`src/`)
- `fetch_attack_data.py` - downloads + cleans MITRE ATT&CK data
- `fetch_cve_data.py` - pulls + cleans recent high-severity CVEs from NVD
  (uses API key from `.env` for higher rate limit)
- `inspect_cicids.py` - unzips CIC-IDS2017 (from Kaggle) and inspects its
  structure
- `convert_cicids_alerts.py` - turns raw network flow data into
  human-readable alert text, tagged with a rough MITRE technique
- `check_alerts.py` - spot-checks sample alerts by category
- `generate_synthetic_alerts.py` - generates synthetic endpoint/cloud/identity
  alerts using the local Llama model, with retry logic for malformed JSON

### Week 1 key decisions
- **Local model over paid API** - zero inference cost, shows understanding
  of deployment tradeoffs and data privacy
- **~300-500 records per public data source, not the full dataset** -
  realistic scope for a portfolio project, not production infra
- **Label-to-ATT&CK-technique mappings in CIC-IDS2017 data are heuristic**,
  not official MITRE annotations - documented as such
- **Kaggle mirror used for CIC-IDS2017** instead of the official
  direct-download link, which appears deprecated/gated now
- **CIC-IDS2017 sampling biased toward "distinctive" flows** (70%) with some
  random sampling (30%) for attack categories - pure random sampling produced
  flat, similar alert text across attack categories
- **Benign traffic later changed to PURE random sampling** (Week 4 fix,
  see below) - distinctive-looking benign flows were causing false alarms
- **Synthetic alert generation uses retry logic** for JSON parsing - local
  models occasionally produce malformed JSON, self-corrects on retry
- **Fixed a real data bug found later (Week 3)**: one technique ID in the
  synthetic alert generator was mistyped ("T121.001" instead of "T1021.001"),
  causing 7 alerts to be evaluated against a technique that didn't exist in
  the knowledge base. Fixed and regenerated.

---

## WEEK 2 - RAG pipeline: embedding, retrieval, generation (COMPLETE)

Goal: turn the Week 1 data into a working system that takes a raw alert and
returns a structured triage assessment.

### What was built

1. **Knowledge base embedding** - all 697 ATT&CK techniques and 307 CVEs
   converted to vectors using `sentence-transformers` (all-MiniLM-L6-v2,
   runs fully local), stored in **two separate ChromaDB collections**
   (not one shared collection - ATT&CK and CVE text are structurally
   different, mixing them caused cross-contamination in early testing)

2. **Retrieval function** - given a new alert, embeds it and queries both
   collections, returns the top matching techniques and CVEs with full
   metadata (technique ID, name, tactics, CVSS score, etc.)

3. **RAG prompt + generation** - the retrieved context gets inserted into a
   prompt template, sent to the local Llama 3.1 8B model, which returns a
   structured JSON assessment: summary, technique_id, severity,
   recommended_action

4. **Validation + retry logic** - parses the model's JSON output, checks all
   required fields are present and valid, and critically: **rejects any
   technique_id the model didn't actually retrieve** (guards against the
   model inventing a plausible-sounding but wrong technique). Retries up to
   3 times on failure.

### Week 2 files (`src/`)
- `build_knowledge_base.py` - embeds ATT&CK + CVE data into two ChromaDB
  collections
- `retrieval.py` - reusable `KnowledgeRetriever` class; given an alert,
  returns structured top-matching techniques + CVEs
- `triage.py` - the full pipeline: retrieve -> build prompt -> generate ->
  validate -> retry. This is the core of the whole project. (Prompt
  significantly revised in Week 4 - see severity calibration fix below.)

### Week 2 key decisions
- **Two separate ChromaDB collections, not one merged collection** - keeps
  ATT&CK and CVE retrieval independent and relevant
- **Metadata attached to every embedding** (technique_id, severity,
  cvss_score, etc.) - retrieval results come back already labeled
- **technique_id validation cross-checks against retrieved matches** - the
  main anti-hallucination guardrail in the system
- **Fail-safe default on total failure**: severity "Medium" (not "Low"),
  flagged for manual review - fails toward caution

---

## WEEK 3 - FastAPI service + evaluation (COMPLETE)

Goal: turn the pipeline into a real callable service, and get an honest,
evidence-backed answer to "how do you know it works."

### What was built

1. **FastAPI wrapper (`main.py`)** - exposes the triage pipeline as a real
   HTTP API (`GET /health`, `POST /triage`), auto-generated docs at `/docs`.
   Loads the retriever once at startup, reused across requests.

2. **Evaluation script (`eval.py`)** - runs all 140 synthetic alerts (known
   ground truth) through the full pipeline, measuring top-1 exact match,
   top-1 same-family match, and recall@3 (exact and same-family), broken
   down by category.

### Evaluation results (full 140 synthetic alerts)

| Metric | Result |
|---|---|
| Top-1 exact match | 32/140 (22.9%) |
| Top-1 same-family match | 49/140 (35.0%) |
| Recall@3 exact | 42/140 (30.0%) |
| Recall@3 same-family | 63/140 (45.0%) |
| Pipeline failures | 0/140 (0%) |

**By category:** Endpoint and Identity had healthy recall@3 (40.8% / 33.9%);
**Cloud was a genuine, isolated weak point (8.6% recall@3)** - a retrieval
problem, not a generation problem, since the correct technique rarely even
made it into the top 3 candidates for cloud alerts. Working hypothesis:
cloud ATT&CK descriptions are more conceptually similar to each other than
something concrete like "PowerShell execution," harder for a small
general-purpose embedding model to discriminate.

### Week 3 files (`src/`)
- `main.py` - FastAPI app
- `eval.py` - evaluation harness

### Week 3 key decisions
- **Added a same-family metric** - strict exact-match was unfairly
  penalizing the model for correctly identifying a more specific
  sub-technique than an overly broad ground-truth label
- **Added recall@3 by category** to diagnose *where* (retrieval vs.
  generation) a weak category's errors came from
- **Chose not to run a paid-API comparison** - costs money, undercuts the
  "$0 total cost" pitch; noted as a possible future addition
- **Found and fixed the T121.001 typo bug via the eval process itself**

---

## WEEK 4 - React dashboard, calibration fix, mobile support (IN PROGRESS)

Goal: build a real UI on top of the working backend, fix a significant
accuracy problem discovered during polish, and prepare for GitHub.

### Dashboard build

Built with **React + TypeScript + Vite + Tailwind CSS v4 + Framer Motion**,
in its own `dashboard/` folder (separate Node project, own
`package.json`/`node_modules`). Framer Motion chosen to match the animation
library already used on the personal portfolio site.

**Design direction:** leans into the "Darkroom" name literally - a dark,
low-light "safelight red" color palette (not generic AI-purple), a
**filmstrip motif** with sprocket-hole perforations running down the left
edge of the alert feed (a structural choice tied to the actual subject
matter, not decoration), monospace type (IBM Plex Mono) for technical
data, and an italic Fraunces serif wordmark for the "Darkroom"/"PD" brand
elements - reusing a font already established on the personal portfolio for
visual consistency across projects.

**Landing sequence:** a splash screen with a large italic Fraunces "PD"
mark. Click triggers a dramatic scale-based zoom-out + dissolve (matching
the exact animation technique already used on the portfolio's own
MH-monogram page transition - scale + opacity, sharp ease-out), followed by
a "developing…" progress bar (on-theme: film literally develops over time
in a darkroom), then the main page reveals.

**Main layout:** two-column landing page, not a bare dashboard -
"DARKROOM" title + italic tagline centered top, live status indicator
below it. Left column: **About panel** - what the project is, a 4-step
"how it works" (Retrieve -> Reason -> Validate -> Report), and a 2x2 "at a
glance" stat grid (697 techniques / 307 CVEs / $0 cost / 100% local).
Right column: the **live demo** - stats bar (received / high-critical /
avg triage time), a **live feed simulation** that automatically pulls real
alerts from the project's own stored data (synthetic + CIC-IDS2017) every
6 seconds and sends them to the real backend with no user input required,
plus a secondary manual "paste an alert" option. A "Built with" tech-stack
tag row anchors the bottom of the page. Fully responsive (mobile-first
Tailwind breakpoints), vertically centered so it doesn't feel sparse on
tall/wide screens.

### Severity calibration bug - found, diagnosed, fixed

While polishing, noticed the live feed skewed heavily High/Critical.
Built `benign_check.py` to specifically test genuinely benign CIC-IDS2017
traffic against the live API - **found 84% of normal, non-attack traffic
was being flagged High/Critical.**

**Two separate root causes, both fixed:**

1. **Sampling bias (Week 1 code):** `convert_cicids_alerts.py`'s
   interestingness-biased sampling was applied to the Benign category too,
   picking statistical *outliers* within normal traffic (unusually high
   throughput, lopsided packet counts) rather than *typical* normal
   traffic - so "benign" alert text still read as alarming. **Fixed:**
   Benign now uses pure random sampling; other categories unchanged.

2. **Prompt design gap (Week 2 code):** retrieval always returns its
   top-N nearest matches even when nothing is genuinely relevant (no
   built-in "reject" threshold) - so a boring alert still got handed
   technique names that read as evidence of a threat. **Fixed:** added a
   `WEAK_MATCH_DISTANCE_THRESHOLD` (1.15, calibrated from Week 2/3
   observed distances) - when the best retrieved match is weaker than
   this, the prompt explicitly tells the model retrieval likely found
   nothing genuinely relevant, and explicitly permits/encourages "Low"
   severity as a normal, frequent, expected outcome for ordinary activity.

**Result, verified with the same measurement tool before/after:**

| | Before | After |
|---|---|---|
| High/Critical on genuinely benign traffic | 84% | **4%** |

**Verified the fix didn't overcorrect** - re-ran the original 3 known-good
test alerts (PowerShell, brute force login, DoS-pattern flow); all still
correctly returned Medium/High, not suppressed to Low.

### Mobile/network testing - two real bugs found and fixed

Tested the live dashboard on a real phone over the same WiFi network (not
just browser emulation). Found and fixed:

1. **Hardcoded `127.0.0.1` in the API client** - meant "this same device,"
   which breaks when the page is loaded from another device on the
   network (the phone). Fixed to derive the API host dynamically from
   `window.location.hostname`, so it works identically whether loaded via
   `localhost` or a LAN IP.

2. **`crypto.randomUUID()` silently unavailable on the phone** - this
   browser API only works in "secure contexts" (HTTPS or `localhost`
   specifically); a page loaded via a plain-HTTP LAN IP doesn't qualify,
   so the function didn't exist, throwing an unhandled error with no
   visible symptom beyond a blank page. Diagnosed using a temporary
   on-screen error overlay (`DebugOverlay.tsx`) built specifically because
   USB phone debugging wasn't cooperating - catches both React render
   errors and uncaught promise rejections and displays them directly on
   the device screen. Fixed with a `generateId()` fallback that only uses
   `crypto.randomUUID` when available, otherwise a manual ID generator.

Also updated FastAPI's CORS `allow_origins` to include the LAN IP, and
both servers now support `--host 0.0.0.0` for network-exposed testing.

### Project cleanup

Removed stray root-level `node_modules/`, `package.json`,
`package-lock.json`, `.package-lock.json` (accidental artifacts from
`npm install` having been run from the wrong folder at some point),
`cicids_run_log.txt`, `cve_run_log.txt`, `src/__pycache__/`, and an unused
`dashboard/public/icons.svg`. Added `data/knowledge_base/` (~14MB,
regenerable ChromaDB binary data) to `.gitignore`.

### Week 4 files (`dashboard/src/`)
- `App.tsx` - main layout, live feed simulation logic, state management
- `components/Splash.tsx` - PD mark, zoom animation, developing progress bar
- `components/AboutPanel.tsx` - left column (what/how/at-a-glance)
- `components/Header.tsx`, `StatsBar.tsx`, `Filmstrip.tsx`, `AlertRow.tsx`,
  `ManualInput.tsx`, `ChevronIcon.tsx` - supporting UI components
- `lib/api.ts` - backend API client (network-safe hostname handling)
- `lib/sampleAlerts.ts` - loads real alert data for the live feed simulation
- `lib/severity.ts` - severity color mapping
- `lib/id.ts` - cross-context-safe ID generator
- `DebugOverlay.tsx` - temporary error-display tool for device debugging
  (safe to remove once no longer needed)

### Week 4 files (`src/`)
- `benign_check.py` - tests genuinely benign traffic against the live API,
  the tool that surfaced the severity calibration bug

### Week 4 key decisions
- **Filmstrip/sprocket-hole motif as the one signature design element** -
  deliberately restrained to a single structural device tied to the
  project's actual name/subject, rather than decorating everywhere
- **Live feed pulls from real stored project data, not fabricated text** -
  an honest simulation of "alerts arriving automatically," explicitly
  documented as such rather than implying a live network feed exists
- **Auto-pause after 3 consecutive backend failures** - prevents the live
  feed from silently hammering a dead backend forever (found the hard way
  after leaving a tab open overnight racked up 500+ failed requests)
- **Compact-by-default, full detail behind a click** - the dashboard never
  shows the full reasoning paragraph inline; matches the original "seconds
  not minutes" pitch rather than contradicting it with a wall of text

---

## Data + folder reference

### `data/`
- `data/raw/` - original downloaded files, untouched (not pushed to GitHub)
- `data/processed/` - cleaned, structured JSON ready for embedding
- `data/knowledge_base/chroma_db/` - persisted vector database (not pushed
  to GitHub - regenerable, ~14MB)

### `dashboard/`
- Separate React/TypeScript/Vite frontend project, own `package.json`
- `dashboard/public/data/` - copies of real alert data for the live feed

### Config / meta files
- `.env` - holds the NVD API key (never committed to git)
- `.gitignore` - excludes venv, raw data, knowledge base, secrets
- `requirements.txt` - Python dependencies

---

## What's next

- [x] Week 1: Data pipeline (ATT&CK, CVE, network alerts, synthetic alerts)
- [x] Week 2: Embedding, retrieval, RAG prompt + generation, validation/retry
- [x] Week 3: FastAPI service, evaluation harness, honest accuracy results
- [x] Week 4: React dashboard, severity calibration fix, mobile support
- [x] Push to GitHub (repo doesn't exist yet - everything is currently
      local only)
- [x] Optional: deploy frontend-only to Vercel (backend stays local)
- [x] Case study writeup (Word doc, planned for later)