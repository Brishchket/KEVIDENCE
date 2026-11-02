# KEVIDENCE

KEVIDENCE is a vulnerability intelligence and risk-prioritization application. It ingests CVE data from the NVD, enriches it with EPSS and CISA Known Exploited Vulnerabilities (KEV) data, and ranks vulnerabilities using a transparent, deterministic score. It also generates evidence-grounded risk narratives for managers, security analysts, and IT administrators.

The risk score is computed by application code, not by an LLM. Generated narrative claims are checked against the collected evidence using semantic similarity and strict fact checks. The web dashboard presents prioritized vulnerabilities, live updates, CVE details, narrative comparisons, evaluation results, and downloadable reports.

[![KEVIDENCE architecture diagram](https://gitdiagram.com/brishchket/kevidence/diagram.png)](https://gitdiagram.com/brishchket/kevidence?utm_source=readme&utm_medium=picture)

## How it works

1. **Ingest:** Fetch CVE records from the NVD and enrich them with EPSS exploit-likelihood scores and CISA KEV status.
2. **Prioritize:** Calculate a deterministic score from CVSS severity (30%), EPSS likelihood (30%), and KEV status (40%). Priority bands and recommended actions are shown in the dashboard.
3. **Explain:** Build an evidence record for each vulnerability and generate narratives for manager, analyst, and IT-admin audiences. The default LLM provider is `mock`; Gemini, OpenAI, and Anthropic providers are also supported.
4. **Verify:** Check each narrative sentence against the evidence, including strict checks for factual details, and attach faithfulness and confidence results.
5. **Explore and report:** Use the Next.js dashboard, API, and PDF reporting endpoints to review CVEs and share findings.

## Repository layout

- `backend/` — FastAPI application, ingestion and scoring pipeline, SQLite storage, CLI, narrative generation and verification, PDF reporting, evaluations, and tests.
- `frontend/` — Next.js dashboard, including CVE details, comparisons, evaluation, and survey views.
- `docs/` — Architecture, evaluation methodology, and known limitations.
- `HUMAN_TODO.md` — Human data-collection and labeling tasks for the project.

## Requirements

- Python 3.11 or later
- Node.js 18 or later and npm
- Optional: API keys for NVD (improves request rate limits) and a configured LLM provider

## Setup

From the repository root, create a local environment file from the example and add any provider keys you plan to use:

```powershell
Copy-Item .env.example .env
```

Install backend dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

Install frontend dependencies:

```powershell
cd frontend
npm install
cd ..
```

The default LLM provider is `mock`, so the application can run without an LLM API key. To use a hosted provider, set `LLM_PROVIDER` to `gemini`, `openai`, or `anthropic` in `.env` and provide that provider's API key. `NVD_API_KEY` is optional.

## Run locally

Start the backend from the repository root:

```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

On startup, the API initializes its SQLite database, seeds demo CVEs if the database is empty, and starts its real-time data supervisor. The API is at <http://localhost:8000>, with interactive documentation at <http://localhost:8000/docs>.

In another terminal, start the frontend:

```powershell
cd frontend
npm run dev
```

Open <http://localhost:3000>. To ingest a larger set of current vulnerabilities, run the CLI from the `backend` directory:

```powershell
python -m app.cli ingest --target 600
```

Generate narratives for the 50 highest-priority CVEs:

```powershell
python -m app.cli narrate --top-n 50 --audiences all
```

Other CLI commands include `watch` for standalone real-time polling, `report` for PDF generation, `rescore` for recalculating priorities, and `evaluate` for the evaluation harness. Run `python -m app.cli --help` from `backend` for command options.

## Tests and evaluation

Run the backend test suite from `backend`:

```powershell
python -m pytest tests
```

Run the evaluation harness:

```powershell
python -m app.cli evaluate
```

Evaluation details and known limitations are documented in [docs/EVALUATION.md](docs/EVALUATION.md) and [docs/LIMITATIONS.md](docs/LIMITATIONS.md). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the application flow and narrative-verification design.
