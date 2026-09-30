# System Limitations & Constraints

PhantomPatch uses a deterministic verifier to constrain LLM hallucinations. While effective, the approach has several known edge cases and limitations.

## Verifier Limitations

1. **Negation Blindness in Embeddings:**
   The `all-MiniLM-L6-v2` embedding model is optimized for semantic similarity but can struggle with direct negations. 
   - *Example:* "This vulnerability is listed in the KEV" vs. "This vulnerability is NOT listed in the KEV" will have a very high cosine similarity.
   - *Mitigation:* The `strict_facts` guard partially mitigates this by requiring exact matches on numbers and dates, but boolean states remain vulnerable to hallucinated negations.

2. **Paraphrased Numeric Data:**
   The `strict_facts` regex guard looks for exact numbers and percentages (with a slight tolerance for fractions/percentages).
   - *Example:* If the LLM writes "nine point eight" instead of "9.8", the regex guard will not catch it, and it will rely solely on the semantic embedding similarity.

3. **Incomplete Product/Vendor Extraction:**
   The `strict_facts` guard conservatively checks product and vendor names. Due to the complexity of CPE strings in the NVD, the parser only extracts the first vendor/product pair. If a vulnerability affects 50 products and the LLM mentions the 2nd product, the simple strict facts guard might flag it if it relies solely on the primary extracted product.

## Pipeline Limitations

1. **Circular KEV Scoring:**
   The KEV list is a boolean flag that heavily impacts the PhantomPatch priority score (40% weight). Measuring KEV recall on the final priority score is inherently circular. We address this in the evaluation harness by including a "KEV-ablated" ranking condition.

2. **CPU Bound Verification:**
   The verifier runs locally using PyTorch (CPU-only). Processing a large batch of narratives (e.g., 600 CVEs x 3 audiences = 1800 narratives) takes significant time locally.

3. **EPSS Delay:**
   EPSS scores are updated daily. A zero-day vulnerability ingested from NVD might not have an EPSS score for 24-48 hours, causing it to receive a lower initial priority score. The system design (upsert-only pipeline) handles this by updating the score on subsequent pipeline runs.
