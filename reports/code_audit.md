# MSLM Code Audit — Phase 1

Paper ID 26012 · baseline commit `c5d408a` (v0.2.0) · branch `revision/icait-2026`
Audit date 2026-10-09 · deadline 2026-10-10

Scope: `src/mslm/{risk,l1,l2,l3,pipeline,experiments,audit}.py`, `tests/`,
`docs/`, `results/`, against the reviewer feedback and the revised manuscript.

Nothing in `src/` or `tests/` was modified during Phase 1. Baseline artifacts are
under `results/baseline/`.

---

## 1. Baseline execution (reproduced)

| Check | Command | Result |
|---|---|---|
| Tests | `python3 -m unittest discover -s tests -v` | `Ran 54 tests ... OK` |
| Experiment | `python3 -m mslm.experiments --iterations 1000 --benchmark-iterations 10000 --seed 2026 --output results/baseline` | exit 0 |

Environment: Python 3.9.6, macOS 15.6 arm64 (Apple M4), commit
`c5d408a2bd61901738785a8129f1a89dec31e3e8`. Full provenance in
`results/baseline/environment.txt`.

Baseline results (fresh run):
- Effectiveness: every chain 1000/1000 blocked, 0 unexpected approvals, 1000/1000
  matched controls accepted, Wilson 95% lower bound 99.617%.
- CCRS raw: C1 9.30, C2 8.67, C3 9.221, C4 9.95345 (deployment cap 9.8).
- Benchmark: median 15.167 us, p95 16.042 us, p99 21.666 us (machine/load
  sensitive; see §5).

---

## 2. Module audit

### 2.1 `risk.py` — CCRS
- Formula: `raw = 10*(1 - ∏(1 - CVSSᵢ/10))`, bounded [0,10], monotone,
  single-score consistent, max-dominant, permutation invariant. Inputs validated
  (`0 ≤ score ≤ 10`, non-empty, cap in `(0,10]`).
- Order-free by construction (python `prod` over a tuple). No reachability,
  prerequisite, trust-boundary, or dependency input exists anywhere.
- Provides only `max_cvss` and `amplification_percent`; **no** mean, capped-sum,
  or sequential-product baselines. This is exactly the gap Reviewer I.2 and
  Reviewer III.1 point at.

Probe (executed):
```
permutation                [8.1,5.9,7.5] == [7.5,8.1,5.9] -> 9.80525 (equal)
same multiset              [7.5,7.2] == [7.2,7.5] -> 9.3
V1 only                    -> 7.5
V1 + unrelated/unreachable V4 -> 8.975   (delta +1.475)
C1 max 7.5 mean 7.35 capped_sum 10 ccrs 9.30
C2 max 6.5 mean 6.35 capped_sum 10 ccrs 8.67
C3 max 8.1 mean 7.00 capped_sum 10 ccrs 9.221
C4 max 8.1 mean 7.325 capped_sum 10 ccrs 9.95345
```
Conclusion: the metric is a **set-severity aggregator**. An irrelevant or
unreachable vulnerability still raises CCRS (Reviewer III.1), and two chains
with the same CVSS multiset are indistinguishable regardless of path. This must
be stated as a limitation and paired with an explicit plausibility gate.

### 2.2 `l1.py` — onboarding analysis
- Python `ast.parse` only (`l1.py:137`). Rules: custom-auth → V1; admin/delete/
  refund without `authoriz*|permission` call → V6; `hashlib.md5|sha1`,
  `random.*` → V4; `.json/.dict` in a function → V5; client `request[...]['amount
  |price']` → V3; `transaction_id|account_id` → V2; hardcoded auth compare → V1.
- Findings deduplicated by `(rule, line)` and given deterministic SHA-based IDs.
- Gate: `deployment_score < approval_threshold(7.0)` → approved; empty findings →
  approved; syntax error → fail closed.
- **Limitation (Reviewer III.2):** this is a Python-AST heuristic detector. It has
  no JavaScript/TypeScript mini-app parser, no bundle/WASM handling, no confidence
  or labeled-corpus precision/recall. `ast.unparse` is used behind a
  `hasattr` guard for py3.9 compatibility.
- The static analyzer is **not** invoked at all in the C1/C4 experiment trials
  (see §3), so the paper currently cannot claim L1 detection for those chains.

### 2.3 `l2.py` — authorization / ownership / minimization
- Deny-by-default RBAC via `PERMISSIONS` + `require_permission`; unauthenticated
  denied; `require_owner` enforces subject==owner; `require_merchant` enforces
  role + merchant_id match.
- `minimize_response` recursively removes `cvv,pin,password,secret,secret_key,
  access_token`, masks `pan/card_number` to last 4, masks `ssn`.
- Well covered (10 tests). Ownership ignores arbitrary attacker subject ids, which
  is why C2's random attacker id does not create genuine variation (§3).

### 2.4 `l3.py` — payment integrity
- HMAC-SHA256 over canonical JSON claims (merchant, user, order, amount_minor,
  currency, issued_at, expires_at, nonce, key_id). Constant-time compare.
- Enforces amount binding, currency, future-issued rejection, expiry, key
  rotation (`KeyRing`), and single-use nonce (`ReplayStore`, thread-locked).
- `amount_to_minor` rejects float drift, NaN/Inf, negatives, over-precision.
- 11 tests. Strong. The only security-relevant experiment variation is here
  (C3 amount tampering), and it is correctly rejected by signature.

### 2.5 `pipeline.py` — integration
- `process()` order: L1 merchant gate → L2 permission+ownership → L3 token verify
  → audit. Returns `Decision(approved, blocked_at, reason)`.
- Short-circuits: an L1 block prevents L2/L3 from ever executing. This is correct
  defense-in-depth behaviour but means a chain attributed to "first layer L1"
  provides **no evidence** about downstream layers.
- `issue_token` requires L2 permission + merchant boundary, then the L1 approval
  flag.
- 8 pipeline tests.

### 2.6 `experiments.py` — methodology (the core weakness)
See §3. Two problems: (a) C1/C4 attacks are flag flips, not detections; (b)
per-chain "variation" is not security-relevant and no trial traces are exported.

### 2.7 `audit.py`
Append-only in-memory structured events; adequate for controlled runs; not
durable. Events are recorded per decision but never exported per trial.

---

## 3. What the C1–C4 experiment actually proves (and does not)

`run_effectiveness` (`experiments.py:31-135`) builds one gateway with
`merchant-1` approved, issues a **valid** token for `user-victim`, then per chain:

| Chain | "Attack" performed | Expected layer | What is really exercised |
|---|---|---|---|
| C1 | `set_merchant_approval("merchant-1", False)` (`:67-68`) | L1 | the approval **flag** only; no code analysis |
| C2 | principal = random `attacker-<n>` (`:70`) | L2 | `require_owner` (behaviourally identical each trial) |
| C3 | `amount_minor = randrange(1,9999)` (`:72-80`) | L3 | HMAC claim binding (genuine variation) |
| C4 | approval `False` + attacker id + `amount=1` (`:81-92`) | L1 | approval flag; V2/V3 never reached |

Proved: given the handler sequence, the gateway returns the expected `blocked_at`
and legitimate controls pass. The C1/C4 result is a **trivial** consequence of
setting the gate to `False` — it demonstrates the gate wiring, not detection of
V1/V6 or any attack chain. C4's claimed V2/V3 steps are never executed. C2's
1000 trials are effectively one repeated case, so its Wilson CI (99.617%) is
**not** a meaningful sampling interval over distinct attacks.

Not proved: that L1 detects malicious or risky mini-app code; that a real
V1→V6→V2→V3 sequence is blocked at each step; that the layers generalize beyond
the hardcoded flag manipulation.

Reviewer I.4 explicitly asks how trials differ — the answer is currently
"barely, and not in security-relevant ways", which must be fixed before the CI
claim is retained.

---

## 4. Paper ↔ code discrepancies

Full matrix in `reports/reviewer_evidence_matrix.md` (D1–D9). Headline items:
- **D1/D2:** C1 & C4 manually set approval False; C4's later stages never run.
- **D3/D4:** C2 varies a field the control ignores; CI over near-identical trials.
- **D5:** no per-trial traceability.
- **D6:** CVSS scalars have no vectors/derivation (Reviewer I.5).
- **D7:** manuscript claims Juice Shop v20.0.0 reproduction; no artifacts exist
  (Reviewer I.6) — `docs/PAPER_EVIDENCE.md:43-57` confirms absence.
- **D9:** README references a paper title "*Quantifying the Unseen*" that does not
  match the submission.

Verified as **consistent** (no change needed): test-count breakdown vs Table V;
CCRS values vs Table VI; performance numbers vs `results/experiment.json`;
environment vs §VII-A.

---

## 5. Reproducibility notes

- Benchmark latency varies run-to-run (p99 15.5–21.7 us observed). The manuscript
  values match the preserved `results/experiment.json`, not the fresh baseline
  run. Report the run actually preserved and state the variance.
- `results/experiment_paper_1000x.json` is an older run (p99 15.458) whose values
  do not match the manuscript; keep it but do not cite it.
- `.venv/` in the repo is empty/broken; system Python 3.9.6 (stdlib-only) was
  used. `pypdf` was installed only in the audit environment to read the reviewer
  PDFs; it is **not** a project dependency.

---

## 6. Phase 1 conclusion

The implementation is clean, well-tested, and honest in its docs, but the
**effectiveness experiment does not test what the paper implies**: C1/C4 do not
exercise L1, C4 skips V2/V3, C2 is effectively deterministic, and the CI is
computed over non-distinct trials. CCRS is mathematically sound but is a
set-severity aggregator with no chain-awareness — consistent with Reviewer I.1
and III.1. CVSS vectors and Juice Shop artifacts are absent.

No source/test changes made yet, per instruction to present findings first.

> **Post-revision note:** the C2 line above (V5=6.2, CCRS 8.67) describes the
> baseline. V5 was later re-derived to 6.5, so the revised C2 CCRS is **8.775**
> and overall Table VI avg CCRS is **9.312363** (`results/revised/`). This audit
> intentionally preserves the as-found baseline.
