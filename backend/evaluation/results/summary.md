# PhantomPatch Evaluation Summary

**Provider:** gemini

## Baseline Comparison

```json
{
  "provider": "gemini",
  "model": "gemini",
  "note": "",
  "n_cves": 50,
  "raw": {
    "flesch_scores": [
      31.5,
      56.2,
      60.5,
      93.5,
      51.8,
      24.0,
      40.9,
      34.9,
      45.3,
      43.9,
      38.7,
      47.6,
      47.5,
      19.9,
      43.3,
      -0.3,
      5.3,
      36.3,
      28.7,
      56.2,
      36.3,
      -3.8,
      46.6,
      -5.4,
      36.0,
      38.1,
      18.4,
      5.3,
      27.5,
      -0.1,
      10.0,
      1.6,
      46.9,
      0.4,
      4.9,
      35.2,
      25.6,
      28.5,
      -7.7,
      -19.7,
      4.5,
      40.1,
      42.6,
      4.6,
      -14.6,
      38.1,
      13.6,
      4.1,
      49.8,
      43.1
    ],
    "unsupported_rates": [
      0.6667,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.8571,
      0.0,
      0.8,
      0.8,
      0.6667,
      0.8333,
      0.5,
      0.3333,
      0.4,
      0.3333,
      0.0,
      0.6,
      0.6,
      0.6,
      0.6667,
      0.4,
      0.8,
      0.0,
      0.6667,
      0.75,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0,
      0.5,
      0.0,
      0.0,
      0.0,
      0.5,
      0.0,
      0.1429,
      0.1429,
      0.0,
      0.25,
      0.0,
      0.0,
      0.1429,
      0.5,
      0.3333,
      0.0,
      0.0,
      0.6667
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
      0.3333,
      0.3333,
      0.0,
      0.0,
      0.0,
      0.0,
      0.6667,
      0.0,
      0.0,
      0.0,
      0.0,
      0.0
    ],
    "mean_flesch": 27.1,
    "mean_unsupported": 0.289,
    "mean_coverage": 0.0333
  },
  "phantompatch": {
    "flesch_scores": [
      27.6,
      35.8,
      40.5,
      58.7,
      43.0,
      34.7,
      48.2,
      44.2,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      55.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      58.7,
      55.7,
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
      58.7
    ],
    "unsupported_rates": [
      0.0,
      0.3333,
      0.0,
      0.25,
      0.6,
      0.0,
      0.3333,
      0.4,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25,
      0.25,
      0.25,
      0.0,
      0.25,
      0.25,
      0.25,
      0.25,
      0.5,
      0.5,
      0.25,
      0.25,
      0.0,
      0.5,
      0.5,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25,
      0.25,
      0.5,
      0.5,
      0.25,
      0.25,
      0.5,
      0.5,
      0.25,
      0.25,
      0.25
    ],
    "coverage": [
      0.25,
      0.25,
      0.5,
      0.6667,
      0.6667,
      0.3333,
      0.3333,
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
      0.6667,
      0.6667
    ],
    "mean_flesch": 55.3,
    "mean_unsupported": 0.3075,
    "mean_coverage": 0.6746
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
  "provider": "gemini",
  "note": "Time-correct forward prediction (T to T+90 days)",
  "snapshot_date": "2026-07-08",
  "total_cves": 4206,
  "target_future_kev_additions": 99,
  "rankings": {
    "weighted_v1": {
      "recall@25": 1.0,
      "recall@50": 1.0,
      "recall@100": 1.0
    },
    "vmc_chain_v1": {
      "recall@25": 1.0,
      "recall@50": 1.0,
      "recall@100": 1.0
    }
  },
  "predictive_metrics": {
    "weighted_v1": {
      "threshold_0.75": {
        "precision": 0.0,
        "recall": 0.0,
        "workload": 0.0
      },
      "threshold_0.50": {
        "precision": 0.0,
        "recall": 0.0,
        "workload": 0.0
      },
      "threshold_0.25": {
        "precision": 0.0029,
        "recall": 0.0303,
        "workload": 0.2473
      }
    },
    "vmc_chain_v1": {
      "threshold_0.75": {
        "precision": 0.0,
        "recall": 0.0,
        "workload": 0.0
      },
      "threshold_0.50": {
        "precision": 0.6667,
        "recall": 0.0202,
        "workload": 0.0007
      },
      "threshold_0.25": {
        "precision": 0.6667,
        "recall": 0.0202,
        "workload": 0.0007
      }
    }
  }
}
```

---

## Verifier Validation

```json
{
  "provider": "gemini",
  "note": "",
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
  "provider": "gemini",
  "note": "",
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

