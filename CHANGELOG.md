# Changelog

## Unreleased — ICAIT 2026 revision (Paper 26012)

- Corrected the C1–C4 harness: the L1 analyzer now runs on real merchant
  submissions instead of a manual approval flag; every trial carries a trace
  (input variation, indicators, per-stage decision, reason, first blocking layer).
- Added `src/mslm/scenarios.py` with deterministic, security-relevant variation
  per chain and matched legitimate controls.
- Added `MSLMGateway.onboard_merchant` so onboarding decisions come from analysis.
- Added CCRS aggregation comparison (max, mean, capped sum, sequential product)
  and an explicit chain-plausibility assessment (prerequisites, trust
  boundaries, evidence).
- Added `plausibility.csv` and `trials.csv` evidence outputs.
- Documented the L1 Python-AST language scope and mini-app deployment limits.
- Test suite 54 → 80.
- Added `reports/` (audit, reviewer matrix, methodology, CVSS, revision notes)
  and `results/baseline/` + `results/revised/` evidence.

## 0.2.0 — 2026-09-14

- Added validated CCRS calculation and severity classification.
- Added L1 onboarding analysis with stable, explainable findings.
- Added L2 deny-by-default authorization, isolation, and data minimisation.
- Added L3 HMAC-SHA256 payment integrity, expiry, rotation, and replay controls.
- Added integrated enforcement pipeline and structured audit events.
- Added deterministic C1–C4 experiments and machine-readable evidence export.
- Added 54 automated unit and integration tests.
- Documented research assumptions, evidence interpretation, and demonstration steps.
