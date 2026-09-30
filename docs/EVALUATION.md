# Evaluation Methodology

PhantomPatch's evaluation harness automatically executes the quantitative assessments required for the project.

## Running the Evaluation
```bash
python -m app.cli evaluate
```
Outputs are saved to `backend/evaluation/results/`.

## The Four Evaluations

### 1. Baseline Comparison (`baseline_comparison.py`)
Compares three conditions:
1. **Raw NVD Description**
2. **Generic LLM** (No evidence constraint, simple prompt)
3. **PhantomPatch Narrative** (Evidence-constrained, verified)

*Metrics:*
- **Flesch Reading Ease:** Target $\ge 60$ (Plain English).
- **Unsupported-Claim Rate:** Target $\le 5\%$.
- **Evidence Coverage:** Target $> 80\%$ of key facts included.

### 2. Priority Ranking (`priority_eval.py`)
Assesses whether the deterministic scoring engine surfaces real risk.

*Metrics:*
- **KEV Recall@N** (N=25, 50, 100): What percentage of KEV-listed vulnerabilities appear in the top N?
- Compares: CVSS-only vs. EPSS-only vs. PhantomPatch vs. KEV-Ablated (CVSS+EPSS renormalized).

### 3. Verifier Validation (`verifier_validation.py`)
Evaluates the core contribution: does the code accurately catch LLM hallucinations?

*Metrics:*
- Computes Precision, Recall, and F1 against Human Labels. Target F1 $\ge 0.85$.
- Performs a Threshold Sweep ($0.50$ to $0.70$) to recommend the optimal cosine similarity cutoff.
- Runs a synthetic adversarial test suite (known wrong numbers, wrong dates) to ensure the `strict_facts` guard trips.

### 4. Survey Analysis (`survey_analysis.py`)
A blinded A/B/C survey of the three audiences (Manager, Analyst, IT Admin).

*Metrics:*
- **Mean Clarity Score (1-5 Likert):** Target $\ge 4.0$.
- **Would Act Rate (Binary):** What percentage of respondents felt they had enough info to make a decision?

**Latest run (10 raters, 165 responses, mock provider):**
- **mean_clarity (`overall_mean_clarity`):** 3.47 (target $\ge$ 4.0 — not met)
- **would_act_rate:** 0.80 (80%)
