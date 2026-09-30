# PhantomPatch – Implementation Progress

## Phase 1: Data Layer (Harden Ingestion)
- [x] Config setup (`backend/app/config.py`) loading `.env`
- [x] Database persistence layer (`backend/app/db.py`) with SQLite tables: `cves`, `epss`, `kev`, `narratives`, `eval_runs`, `survey_responses`, `events`, `pipeline_runs`
- [x] NVD REST API client (`backend/app/ingestion/nvd.py`) with chunked date windows, optional API key, and exponential backoff
- [x] EPSS client (`backend/app/ingestion/epss.py`) with batching, probability, and percentile
- [x] CISA KEV client (`backend/app/ingestion/kev.py`) with full metadata fields
- [x] CVE parser (`backend/app/ingestion/parser.py`) with CVSS v3.1/v3.0/v2 extraction, attack vector, patch references, vendor/product parsing from CPEs, and graceful exception logging
- [x] Pipeline orchestrator (`backend/app/ingestion/pipeline.py`) with parse rate tracking
- [x] CLI interface (`backend/app/cli.py`) with `ingest`, `narrate`, `evaluate` subcommands

## Phase 2: Prioritization Engine (Deterministic, No ML)
- [x] Composite priority formula implementation (`backend/app/scoring/scorer.py`): `0.3*(CVSS/10) + 0.3*EPSS + 0.4*KEV`
- [x] Weighted contribution breakdown & `missing_signals` tracking
- [x] Threshold mapping (`CRITICAL >= 0.75`, `HIGH >= 0.50`, `MEDIUM >= 0.25`, `LOW < 0.25`)
- [x] Unit tests (`backend/tests/test_scorer.py`) for boundary conditions and breakdown checks

## Phase 3: Evidence Object
- [x] Pydantic v2 `Evidence` model (`backend/app/schemas.py`)
- [x] Evidence builder (`backend/app/evidence/builder.py`) supporting async and sync instantiation
- [x] Deterministic template-driven `reasons[]` and `recommended_action` mapping
- [x] Plain-English verbalizer (`backend/app/evidence/verbalizer.py`) converting evidence to 1-fact-per-sentence reference sets

## Phase 4: Evidence-Grounded Narratives
- [x] Abstract `LLMClient` interface (`backend/app/llm/base.py`)
- [x] Gemini (`backend/app/llm/gemini.py`), OpenAI (`backend/app/llm/openai.py`), and Anthropic (`backend/app/llm/anthropic.py`) providers
- [x] Deterministic template-based `MockLLMClient` (`backend/app/llm/mock.py`) with unsupported sentence injection toggle
- [x] Prompt management (`backend/app/llm/prompts.py`) supporting versioning (`v1`) and 3 audiences: Manager, Security Analyst, IT Admin
- [x] Narrative generator orchestrator (`backend/app/narrative/generator.py`) handling generation, verifier execution, retry loops, and SQLite caching

## Phase 5: Faithfulness Verifier (Core Contribution)
- [x] Sentence tokenizer using NLTK with regex fallback (`backend/app/verification/verifier.py`)
- [x] Sentence embeddings via `sentence-transformers` (`all-MiniLM-L6-v2`) and cosine similarity matrix
- [x] `strict_facts` guard extracting numbers, percentages, dates, CVE IDs, and verifying against evidence
- [x] Automated retry loop (`RETRY_BELOW = 0.95`, `MAX_RETRIES = 2`) with rewrite prompts
- [x] Confidence label calculation (`HIGH >= 0.95`, `MEDIUM >= 0.80`, `LOW < 0.80`) based strictly on measured faithfulness

## Phase 6: API Layer (FastAPI)
- [x] Application lifecycle and CORS middleware (`backend/app/main.py`)
- [x] Automatic demo data seeding from fixtures on initial startup
- [x] CVE routes (`backend/app/routers/cves.py`): `/api/cves`, `/api/cves/{id}`, `/api/cves/{id}/narratives`, `/api/stats`, `/api/compare/{id}`
- [x] Ingestion routes (`backend/app/routers/ingest.py`): background trigger & status tracking
- [x] Survey & evaluation summary routes (`backend/app/routers/survey.py`)

## Phase 7: Frontend (Next.js App Router)
- [x] Next.js cybersecurity command center UI components
- [x] Dashboard page (`/`) with KPI cards and CVE table
- [x] Detail page (`/cve/[id]`) with audience tabs, sentence highlighting (green/red), tooltips, confidence badges
- [x] Comparison page (`/compare`) contrasting Raw NVD vs. PhantomPatch
- [x] Evaluation summary page (`/evaluation`)
- [x] Blinded survey UI (`/survey`)
- [x] API utility (`frontend/lib/api.ts`)

## Phase 8: Evaluation Harness
- [x] Baseline comparison runner (`backend/evaluation/baseline_comparison.py`) measuring Flesch Reading Ease, unsupported-claim rate, and evidence coverage
- [x] Priority ranking evaluator (`backend/evaluation/priority_eval.py`) computing KEV recall@N (25, 50, 100) and KEV-ablated rankings
- [x] Verifier validation script (`backend/evaluation/verifier_validation.py`) with dataset CSV exporter, threshold sweep, and synthetic adversarial checks
- [x] Survey analysis module (`backend/evaluation/survey_analysis.py`) calculating mean/SD Likert scores
- [x] Evaluation master runner (`backend/evaluation/run_all.py`) exporting JSON/MD summaries

## Phase 9: Quality & Project Documentation
- [x] Offline test suite (`backend/tests/`) covering scorer, evidence, verifier, narrative pipeline, parser, and API TestClient
- [x] Backend `requirements.txt` updated with `sentence-transformers`, `scikit-learn`, `nltk`, etc.
- [x] Comprehensive `README.md` rewrite (installation, ingestion, execution, evaluation instructions)
- [x] Architectural overview (`docs/ARCHITECTURE.md`) with Mermaid diagrams
- [x] Verifier limitations guide (`docs/LIMITATIONS.md`)
- [x] Evaluation reproduction guide (`docs/EVALUATION.md`)
- [x] Scaffolded `HUMAN_TODO.md` (~20% human evaluation protocol)
