# Reviewer-to-Code Audit Matrix (Phase 1)

Paper ID: 26012
Title: A Cumulative Chained Risk Metric for Securing FinTech Mini-App Ecosystems
Baseline commit: c5d408a (main), audit performed on branch `revision/icait-2026`
Dates: audit 2026-10-09; conference deadline 2026-10-10

Legend for status:
- ADDRESSED (code)  : implemented and directly tested
- PARTIAL (code)    : implemented but incompletely or not traceably tested
- DOC ONLY          : acknowledged in docs but not enforced/measured in code
- NOT ADDRESSED     : no supporting implementation or evidence

---

## Reviewer I

| # | Reviewer comment (verbatim gist) | Code / artifact evidence | Status | Required action |
|---|---|---|---|---|
| I.1 | "chained risk" is misleading: CCRS is permutation invariant and ignores order, prerequisites, reachability, dependency; clarify in what sense it is a chain | `src/mslm/risk.py:57` `raw = 10*(1-prod(1-v/10))` — set-only, order-free; `PAPER_CHAINS` at `risk.py:71-76` stores unordered tuples | NOT ADDRESSED | Add explicit attack-chain **plausibility assessment** (prerequisites, trust boundaries, evidence) before grouping; state permutation invariance + "same CVSS ⇒ same CCRS regardless of path" (see R III.1) |
| I.2 | CCRS > max CVSS is expected from the formula; add stronger comparison with other aggregations / evidence of better prioritization | `risk.py` exposes only `max_cvss` and `amplification_percent`; no mean, capped-sum or sequential-product baselines; `experiments.risk_rows()` (`experiments.py:213`) exports CCRS only | PARTIAL | Add max/mean/capped-sum/sequential-product comparison; run irrelevant-vulnerability sensitivity; distinguish math behavior from empirical superiority |
| I.3 | 4,000 synthetic trials must not be presented as general security effectiveness | `docs/PAPER_EVIDENCE.md:25`, `docs/TESTING_GUIDE_FOR_PROFESSOR.md:113`, `experiment.json.limitations` already warn against "100% prevention proven" | DOC ONLY | Keep caveat; add manuscript wording. Underlying trials are weaker than "attack-chain" (see I.4) |
| I.4 | Explain how the 1,000 trials per chain are generated and how they differ; this determines the meaning of the 95% CI | `experiments.py:42-92`: per chain only `index` (order id/`now`) changes. C1 variation = set approval `False` (`:67-68`); C2 variation = random **attacker** subject id (`:70`) which `require_owner` (`l2.py:40-42`) ignores; C3 = random `amount_minor` (`:72-80`); C4 = approval `False` + attacker id + `amount=1` (`:81-92`) | NOT ADDRESSED | Make variations security-relevant and traceable; emit per-trial records (input, indicator, decision, reason, first blocking layer); recompute CI honestly |
| I.5 | CVSS values are author-assigned; provide CVSS vectors or derivation | `l1.py:11-18` hardcodes scalars only (V1=7.5 … V6=7.2); no vectors anywhere in repo | NOT ADDRESSED | Provide justified CVSS v3.1 vectors + scenario assumptions, or explicitly relabel as scenario inputs (`reports/cvss_justification.md`) |
| I.6 | Relationship between Juice Shop experiments and the Python prototype is unclear; state which scenarios were reproduced where | No Juice Shop artifacts in repo; `docs/PAPER_EVIDENCE.md:43-57` says artifacts do not exist; `docs/TESTING_GUIDE_FOR_PROFESSOR.md:225-229` says "Not by the bundled synthetic experiment" | NOT ADDRESSED (manuscript claim) | Either produce preserved Juice Shop artifacts (digest, scripts, traces) or **correct the manuscript** to say only the Python harness was run |

## Reviewer II

| # | Reviewer comment (verbatim gist) | Code / artifact evidence | Status | Required action |
|---|---|---|---|---|
| II.1 | Add theory; use the established term "Mini-App Ecosystem Security" / "FinTech Security Frameworks" | N/A (writing) | N/A | Editorial; ensure terminology consistency |
| II.2 | Explain how L1 maps to onboarding, how L2 controls API security, how L3 proves payment integrity | L1 `l1.py`; L2 `l2.py`; L3 `l3.py`; pipeline `pipeline.py`; mapping table in manuscript Table IV | PARTIAL | Provide explicit code-level mapping from claims → tests → mechanism (`reports/reviewer_evidence_matrix.md` + README) |
| II.3 | Explain limitations from your own experience | `SECURITY_MODEL.md`, `PAPER_EVIDENCE.md` | DOC ONLY | Add honest first-person limitation discussion (AST scope, in-memory state, microbenchmark) |
| II.4 | Clearly describe how MSLM secures mini-app ecosystems | `pipeline.MSLMGateway` integrates all layers; `tests/test_pipeline.py` covers 8 paths | PARTIAL | Add end-to-end description tied to actual enforced controls |

## Reviewer III

| # | Reviewer comment (verbatim gist) | Code / artifact evidence | Status | Required action |
|---|---|---|---|---|
| III.1 | Explain how vulnerability sets qualify as attack chains; define how a plausible chain is established before aggregation; state two sets with equal CVSS get equal CCRS even if paths differ; discuss whether an unreachable/irrelevant weakness raises the score | No chain-plausibility logic exists; `risk.py` aggregates any iterable irrespective of reachability; `PAPER_CHAINS` are hardcoded tuples | NOT ADDRESSED | Implement/document a plausibility gate (prerequisites, trust-boundary crossings, supporting evidence); demonstrate unreachable-vulnerability inflation with an explicit test |
| III.2 | Clarify implementation relevance to mini apps: L1 parses Python AST but the use case is third-party mini-app code; state what L1 analyzes, its relation to a real onboarding submission, and deployment limits | L1 uses `ast.parse` (`l1.py:137`) and Python-specific rules; README/`SECURITY_MODEL.md` note "known Python indicators"; manuscript frames mini-apps as browser-like JS/TS bundles | NOT ADDRESSED (docs) | Document Python-AST limitation, mini-app language mismatch, required translation layer, and resulting deployment-claim limits |

---

## Cross-cutting implementation discrepancies (paper ↔ code)

| ID | Discrepancy | Evidence |
|---|---|---|
| D1 | C1 and C4 "attacks" are not code/attack-chain detections: the harness manually sets `merchant_status=False`. They only test the L1 approval flag, never the L1 static analyzer. | `experiments.py:67-68`, `:81-82`; `pipeline.py:68-69` |
| D2 | C4 claims V1→V6→V2→V3 but is blocked at the L1 gate, so V2 (IDOR) and V3 (price) controls are never exercised in C4. | `experiments.py:81-92`, `pipeline.py:67-69` short-circuits |
| D3 | C2 "variation" randomises attacker subject id, which the ownership check ignores; every C2 trial is behaviourally identical. | `experiments.py:70`; `l2.py:40-42` |
| D4 | The 95% Wilson CI is computed over trials that are (near-)identical, so it does not represent sampling variability of distinct attacks. | `experiments.py:119-135`; generations above |
| D5 | Trials are not individually traceable: only aggregate counts are exported; no per-trial input/decision/reason record. | `experiments.py:36-135` |
| D6 | CVSS inputs are bare scalars with no derivation/vector. | `l1.py:11-18`; `risk.py:71-76` |
| D7 | Manuscript §VII-A claims Juice Shop v20.0.0 reproduction; no artifacts exist. | `docs/PAPER_EVIDENCE.md:43-57` |
| D8 | `docs/PAPER_EVIDENCE.md:61-62` says Table III average CCRS is ~9.28 (not 9.91); the current revised manuscript already reports 9.286, so this specific note is stale but confirms earlier numeric drift. | `docs/PAPER_EVIDENCE.md`; manuscript Table VI |
| D9 | Repository title subject line references "*Quantifying the Unseen*" (README:8), which is not the manuscript title. | `README.md:8` |

## Facts verified during Phase 1

- Test suite: `Ran 54 tests ... OK` (10 CCRS, 11 L1, 10 L2, 11 L3, 8 pipeline, 4 experiment).
- Test-count breakdown in manuscript Table V matches the actual files exactly.
- Baseline experiment reproduced: all chains 1000/1000 blocked, controls 1000/1000 accepted.
- CCRS values in the manuscript (C1 9.30, C2 8.67, C3 9.221, C4 9.95345; amplification 24.0/33.38/13.84/22.88, mean 23.53%) match `risk.py` computation.
- Manuscript performance numbers match `results/experiment.json` (median 15.042, p95 15.417, p99 17.334 us) exactly.
- Environment: Python 3.9.6, macOS 15.6 arm64 (Apple M4) — matches manuscript §VII-A.

---

# Post-Revision Status (Phases 2–6)

Branch `revision/icait-2026`. All changes are additive/behaviour-preserving for
existing functionality. Evidence in `results/revised/`.

| Comment | Status after revision | Evidence |
|---|---|---|
| I.1 chain semantics | Addressed in code+docs | `risk.assess_chain_plausibility`, `plausibility.csv`, `test_plausibility.py`, `SECURITY_MODEL.md`; manuscript wording still required (A3) |
| I.2 aggregation comparison | Addressed (evidence) | `risk.compare_aggregations`, `ccrs.csv` columns; manuscript wording required (A4) |
| I.3 no over-claim | Partly code, needs wording | `experiment.json.limitations`, `experiment_methodology.md` §6; manuscript wording (A2) |
| I.4 trial generation/variation/CI | Addressed | `scenarios.py`, `trials.csv`, `effects.csv.distinct_attack_inputs`, `experiment_methodology.md` |
| I.5 CVSS vectors | Assessed; V5 unresolved | `reports/cvss_justification.md`; author must publish vectors and re-derive V5 |
| I.6 Juice Shop vs Python | Flagged for correction | no artifacts; `manuscript_revision_notes.md` A1 |
| II.1 terminology/theory | Not code; drafting | manuscript task |
| II.2 layer mapping | Addressed (evidence) | `reviewer_evidence_matrix.md` + `experiment_methodology.md`; manifest in README |
| II.3 limitation honesty | Addressed (docs) | `SECURITY_MODEL.md`, `PAPER_EVIDENCE.md`, `experiment_methodology.md` |
| II.4 how MSLM secures ecosystem | Addressed (evidence)+draft | pipeline tests, mapping table |
| III.1 chain qualification / unreachable raises score | Addressed | plausibility gate + `test_plausibility.py::test_unreachable_or_irrelevant_vulnerability_still_raises_ccrs` |
| III.2 L1 Python vs JS/TS | Addressed (docs) | `SECURITY_MODEL.md` "L1 language scope and mini-app representation" |

## Tests added

- `tests/test_scenarios.py` — 11 tests (L1 actually runs; C4 short-circuit; C2
  ownership+minimisation; C3 weak-crypto approve then L3 block; variation;
  determinism; required trace fields).
- `tests/test_plausibility.py` — 11 tests (aggregator comparison; permutation
  invariance; unreachable-vulnerability inflation; plausibility gate).
- `tests/test_pipeline.py` — +3 onboarding-integration tests.
- `tests/test_experiments.py` — +2 tests (real variation/layer; new artifacts).

Total: 54 → 80 tests, all passing (`results/revised/tests.log`).

## Remaining author actions (cannot be done from the artifact)

1. Publish CVSS v3.1 vectors. **V5 re-derived 6.2 → 6.5** (done in code + Table VI;
   author should verify with the FIRST.org calculator).
2. Correct or support the Juice Shop claim.
3. Apply manuscript wording changes A1–A10 (`reports/manuscript_revisions_paste_ready.md`).
4. Commit/push the revision (done on branch `revision/icait-2026`).
