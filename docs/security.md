# Security review

## Threat model

An adversary can submit malformed or resource-heavy flow metadata, poison the baseline CSV, probe scores, or replace a writable artifact. Protect availability, model integrity, flow privacy, and the API credential. A high anomaly score may cause analyst workload even without an actual attack.

## Controls and trust boundaries

- Pydantic requires explicit bounded numeric flow fields and rejects extra fields, missing values, NaN, and infinity. Feature extraction is fixed-cost and performs no network I/O.
- Body size, batch size, worker count, admission wait, and inference timeout limit resource exhaustion. Apply per-client rate limits and TLS at a gateway.
- Production requires a strong shared API key checked with constant-time comparison. Use server-side identity and authorization at the gateway for multi-tenant deployments; opaque IDs are not authorization.
- The adapter requires known CIC columns, maps supported labels explicitly, and reports invalid/unsupported rows. Training keeps group IDs disjoint, removes exact duplicate features, and fits only on benign training data. Review the source for poisoning.
- The model is fixed-schema JSON with finite numeric tensors, size cap, and SHA-256 checksum; no pickle/joblib deserialization occurs. Protect release provenance separately.
- Logs include route template, status, and latency only; no IPs, raw flows, keys, or payloads. Docker runs non-root with read-only filesystem and dropped capabilities. CI runs Ruff, mypy, pytest, Bandit, and pip-audit.

## OWASP considerations and residual risks

There is no user-driven shell execution, SQL query, URL fetch, or packet processing. Errors are generic. Timed-out workers may finish after the HTTP response but stay counted until completion. Shared-key mode lacks tenant roles. Baseline contamination, drift, probing, false positives, and false negatives remain risks. Use reviewed artifacts, gateway quotas, monitoring, and analyst decisions.
