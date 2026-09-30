<<<<<<< HEAD
# PhantomPatch: Evidence-Grounded Vulnerability Risk Narrative Engine

PhantomPatch is a complete pipeline for ingesting vulnerability data, computing a transparent priority score, and generating audience-specific risk narratives (Manager, Security Analyst, IT Admin). 

Crucially, **the risk decision is made by deterministic code, not the LLM.** The LLM's only job is to explain the evidence in plain English. Every sentence the LLM generates is checked by an embedding-based faithfulness verifier. 

## Project Structure

*   `backend/`: Python backend (FastAPI, SQLite, CLI, Verifier, LLM clients)
    *   `app/`: Core application package (ingestion, scoring, evidence, narrative, verifier, routers)
    *   `evaluation/`: Scripts to run baseline comparisons, priority eval, verifier validation, and survey analysis
    *   `tests/`: Pytest suite
*   `frontend/`: Next.js App Router application (Dashboard, CVE Detail, Compare, Evaluation, Survey)
*   `docs/`: Architecture, Limitations, and Evaluation methodology

## Setup & Installation

### 1. Backend Setup

Prerequisites: Python 3.11+ (Windows 10/11 with Git Bash recommended). No Docker required.

```bash
cd backend
python -m venv venv
source venv/Scripts/activate  # Windows Git Bash
pip install -r requirements.txt
```

Set up your environment variables:
```bash
cp ../.env.example ../.env
```
Edit `../.env` and provide your API keys (e.g., `GEMINI_API_KEY`, `NVD_API_KEY` - optional but recommended).

### 2. Frontend Setup

Prerequisites: Node.js 18+

```bash
cd frontend
npm install
```

## Running the Application

### Step 1: Ingest Data
Run the ingestion pipeline to fetch CVEs, enrich them with EPSS and KEV data, and compute priority scores.

```bash
cd backend
# Fetch ~600 CVEs
python -m app.cli ingest --target 600
```

### Step 2: Generate Narratives
Generate evidence-grounded narratives for the highest-priority CVEs. This will invoke the LLM, run the verifier, and execute the retry loop if claims are unsupported.

```bash
# Generate narratives for the top 50 CVEs for all 3 audiences
python -m app.cli narrate --top-n 50 --audiences all
```

### Step 3: Start the Backend API
```bash
# From the backend directory
uvicorn app.main:app --reload --port 8000
```
The API is available at `http://localhost:8000`. Swagger UI at `http://localhost:8000/docs`.

### Step 4: Start the Frontend UI
```bash
# In a new terminal, from the frontend directory
npm run dev
```
Open `http://localhost:3000` in your browser.

## Running Tests and Evaluations

To run the offline unit test suite:
```bash
cd backend
pytest tests/
```

To run the automated evaluation harness:
```bash
cd backend
python -m app.cli evaluate
```

## The Human 20%
This codebase represents the ~80% of the project that can be scaffolded and verified by code. The remaining 20% requires real-world data gathering, human labeling of the verifier output, and survey distribution. See `HUMAN_TODO.md` for the exact protocol.
=======
# KEVIDENCE
>>>>>>> 76bf3291aeb620ee1f005ad49652e286f8ba1f40
