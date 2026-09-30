# PhantomPatch Evaluation Summary

**Provider:** mock

## Report metrics (survey)

| Metric | Value |
| --- | --- |
| Raters | 10 (PASS) |
| **mean_clarity** (`overall_mean_clarity`) | **3.47** (target ≥ 4.0) |
| **would_act_rate** | **0.80** (80%) |

The harness still tags this run `PIPELINE TEST ONLY, not reportable` because `LLM_PROVIDER=mock`.

## Baseline Comparison

```json
{
  "provider": "mock",
  "model": "mock-template-v1",
  "note": "PIPELINE TEST ONLY, not reportable",
  "n_cves": 50,
  "raw": {
    "flesch_scores": [
      31.5,
      56.2,
      60.5,
      40.9,
      45.3,
      43.9,
      38.7,
      47.6,
      24.0,
      36.3,
      28.7,
      56.2,
      5.3,
      46.6,
      36.0,
      27.5,
      36.3,
      38.1,
      -5.4,
      5.3,
      18.4,
      35.2,
      25.6,
      28.5,
      19.9,
      40.1,
      4.9,
      1.6,
      -0.1,
      -14.6,
      46.9,
      42.6,
      -7.7,
      -19.7,
      4.6,
      4.5,
      0.4,
      13.6,
      4.1,
      10.0,
      -3.8,
      16.7,
      43.3,
      42.7,
      55.6,
      42.2,
      49.8,
      48.0,
      48.0,
      27.5
    ],
    "unsupported_rates": [
      0.6667,
      0.0,
      0.0,
      0.8571,
      0.8,
      0.8,
      0.6667,
      0.8333,
      0.0,
      0.6,
      0.6,
      0.6,
      0.0,
      0.8,
      0.6667,
      0.0,
      0.6667,
      0.75,
      0.0,
      0.0,
      0.0,
      0.0,
      0.5,
      0.0,
      0.3333,
      0.25,
      0.0,
      0.0,
      0.0,
      0.1429,
      0.5,
      0.0,
      0.1429,
      0.1429,
      0.0,
      0.0,
      0.0,
      0.3333,
      0.0,
      0.0,
      0.4,
      0.0,
      0.6667,
      0.6,
      0.6,
      0.6,
      0.0,
      0.0,
      0.0,
      0.0
    ],
    "coverage": [
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.3333,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.6667,
      0.0,
      0.0,
      0.6667,
      0.6667,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0
    ],
    "mean_flesch": 26.6,
    "mean_unsupported": 0.2904,
    "mean_coverage": 0.0467
  },
  "phantompatch": {
    "flesch_scores": [
      53.5,
      53.5,
      53.5,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      55.7,
      55.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7
    ],
    "unsupported_rates": [
      0.2,
      0.2,
      0.2,
      0.25,
      0.5,
      0.5,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25,
      0.5,
      0.25,
      0.5,
      0.5,
      0.25,
      0.5,
      0.5,
      0.25,
      0.25,
      0.5,
      0.5,
      0.5,
      0.5,
      0.25,
      0.25,
      0.0,
      0.0,
      0.5,
      0.25,
      0.5,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25,
      0.25
    ],
    "coverage": [
      0.5,
      0.5,
      0.5,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      0.6667,
      1.0,
      1.0,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667,
      0.6667
    ],
    "mean_flesch": 58.3,
    "mean_unsupported": 0.332,
    "mean_coverage": 0.7567
  },
  "targets": {
    "flesch_min": 60,
    "unsupported_max": 0.05
  },
  "pass_fail": {
    "flesch": "FAIL",
    "unsupported": "FAIL"
  }
}
```

---

## Priority Eval

```json
{
  "provider": "mock",
  "model": "N/A (scoring only)",
  "note": "PIPELINE TEST ONLY, not reportable",
  "total_cves": 4140,
  "total_kev": 3,
  "rankings": {
    "phantompatch": {
      "recall@25": 1.0,
      "recall@50": 1.0,
      "recall@100": 1.0
    },
    "cvss_only": {
      "recall@25": 0.0,
      "recall@50": 0.0,
      "recall@100": 0.0
    },
    "epss_only": {
      "recall@25": 0.3333,
      "recall@50": 0.3333,
      "recall@100": 0.6667
    },
    "kev_ablated": {
      "recall@25": 0.3333,
      "recall@50": 0.3333,
      "recall@100": 0.3333
    }
  },
  "circularity_note": "KEV recall on the PhantomPatch score is partly circular because KEV accounts for 40% of the score. The kev_ablated ranking removes this component and uses only CVSS + EPSS (renormalized) for a fairer comparison."
}
```

---

## Verifier Validation

```json
{
  "provider": "mock",
  "note": "PIPELINE TEST ONLY, not reportable",
  "export": {
    "exported": 50,
    "supported_count": 25,
    "flagged_count": 25,
    "path": "C:\\Users\\anike\\Desktop\\proto\\PhantomPatch\\backend\\evaluation\\labeling\\verifier_labels.csv",
    "note": "Existing labeled file preserved (not overwritten)"
  },
  "scoring": {
    "n_labeled": 50,
    "agreement": 0.54,
    "precision": 0.76,
    "recall": 0.5278,
    "f1": 0.623,
    "target_f1": 0.85,
    "f1_pass": false,
    "threshold_sweep": [
      {
        "threshold": 0.5,
        "precision": 0.7179,
        "recall": 0.7778,
        "f1": 0.7467
      },
      {
        "threshold": 0.55,
        "precision": 0.8,
        "recall": 0.6667,
        "f1": 0.7273
      },
      {
        "threshold": 0.6,
        "precision": 0.7692,
        "recall": 0.5556,
        "f1": 0.6452
      },
      {
        "threshold": 0.65,
        "precision": 0.6842,
        "recall": 0.3611,
        "f1": 0.4727
      },
      {
        "threshold": 0.7,
        "precision": 0.6667,
        "recall": 0.3333,
        "f1": 0.4444
      }
    ],
    "recommended_threshold": 0.5
  },
  "synthetic_adversarial": {
    "label": "SYNTHETIC \u2014 sanity check only, not a substitute for human labels",
    "total": 5,
    "caught": 5,
    "catch_rate": 1.0,
    "details": [
      {
        "sentence": "CVE-2024-SYNTH has a CVSS score of 7.5.",
        "faithfulness": 0.0,
        "caught": true
      },
      {
        "sentence": "This vulnerability was exploited by APT29 against government agencies.",
        "faithfulness": 0.0,
        "caught": true
      },
      {
        "sentence": "The EPSS probability is 0.12, indicating low risk.",
        "faithfulness": 0.0,
        "caught": true
      },
      {
        "sentence": "A patch was released on 2024-06-30.",
        "faithfulness": 0.0,
        "caught": true
      },
      {
        "sentence": "The vulnerability affects Microsoft Windows Server 2022.",
        "faithfulness": 0.0,
        "caught": true
      }
    ]
  }
}
```

---

## Survey Analysis

```json
{
  "provider": "mock",
  "note": "PIPELINE TEST ONLY, not reportable",
  "n_raters": 10,
  "n_responses": 165,
  "conditions": {
    "": {
      "n_responses": 90,
      "mean": 2.64,
      "sd": 1.19
    },
    "C": {
      "n_responses": 25,
      "mean": 4.4,
      "sd": 0.49
    },
    "A": {
      "n_responses": 25,
      "mean": 4.8,
      "sd": 0.4
    },
    "B": {
      "n_responses": 25,
      "mean": 4.2,
      "sd": 0.4
    }
  },
  "overall_mean_clarity": 3.47,
  "would_act_rate": 0.8,
  "targets": {
    "min_raters": 10,
    "min_mean_clarity": 4.0
  },
  "pass_fail": {
    "raters": "PASS",
    "mean_clarity": "PENDING (mean=3.47)"
  }
}
```

---

