# The Human 20% - Final Execution Protocol

The KEVIDENCE codebase provides the infrastructure and the automation (the 80%). The remaining 20% requires human execution in the real world to prove the system works. Follow these exact steps to generate the metrics for your final university report.

## Step 1: Initial Setup & Data Fetching
1. Get a free Gemini API key (or OpenAI/Anthropic).
2. Get a free NVD API key.
3. Open the `.env` file in the `backend` folder and paste your keys there.
4. Open a terminal in the `backend` folder and fetch the real data:
   ```bash
   python -m app.cli ingest --target 600
   python -m app.cli narrate --top-n 50 --audiences all
   ```

## Step 2: Generate the Blank Labeling CSV
You must manually grade a sample of the verifier's decisions to prove it is accurate.
1. Run the evaluation command:
   ```bash
   python -m app.cli evaluate
   ```
2. The terminal will say "SKIPPED: needs human labels", but it will quietly generate a new file for you at: `backend/evaluation/labeling/verifier_labels.csv`.

## Step 3: Do the Human Labeling (Grade the Grader)
1. Open `backend/evaluation/labeling/verifier_labels.csv` in Excel or VS Code.
2. Read the `sentence` (what the LLM wrote) and the `matched_evidence` (the facts).
3. In the empty **`human_label`** column, type **`supported`** if the LLM told the truth, or **`unsupported`** if it hallucinated or got a number wrong.
4. Do this for all 50 rows and **save the file**.

## Step 4: Get Your Verifier F1 Score
1. Go back to your terminal and run the exact same command again:
   ```bash
   python -m app.cli evaluate
   ```
2. The script will now compare your human labels against its own automated grades.
3. Open `backend/evaluation/results/summary.json` (or look in the terminal) under `verifier_validation`. The **`f1`** score is the metric you put in your university report to prove the algorithm works!

## Step 5: Conduct the User Survey
You must test the narratives with real people to prove the audience targeting works.
1. Start the backend (`uvicorn app.main:app --reload`) and frontend (`npm run dev`).
2. Send the frontend Survey URL (`http://localhost:3000/survey`) to at least **10 participants** (classmates, friends, colleagues).
3. Once 10 people finish it, run `python -m app.cli evaluate` one last time.
4. Look in the summary file for the **`mean_clarity`** score and the **`would_act_rate`**. Put these numbers in your final report.
