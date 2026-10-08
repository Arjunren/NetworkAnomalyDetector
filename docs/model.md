# Model card — NetworkAnomalyDetector 1.0.0

| Field | Description |
| --- | --- |
| Purpose | Surface unusual network-flow metadata for analyst review. |
| Model type | StandardScaler and PCA reconstruction error, fit only on benign training rows. |
| Training dataset | Operator-prepared CIC-IDS2017 flow CSVs; external data not bundled. |
| Feature set | 12 validated numeric flow fields and 6 deterministic packet/byte/rate features. |
| Evaluation metrics | Held-out precision, recall, F1, ROC-AUC, PR-AUC, FPR, FNR, confusion matrix, and support, stored per training run. No default benchmark score claimed. |
| Known limitations | Linear baseline; old lab traffic; no packet content or temporal sequence modeling. |
| Bias considerations | Benign baseline may underrepresent unusual services or schedules, creating uneven false-positive rates. |
| Security considerations | Protect baseline against poisoning, validate JSON artifact provenance, and never log sensitive flows. |
| Intended use | Investigation prioritization and SIEM enrichment. |
| Out-of-scope use | Confirmed attack attribution or automatic blocking. |
| Version | JSON format `network-pca-anomaly-v1`; model version set at training. |

`anomaly_score` is reconstruction error. `baseline_percentile` and `risk_score` are positions relative to benign validation scores, not probabilities of maliciousness. The flag is an operational threshold only.
