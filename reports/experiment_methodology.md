# Experiment Methodology (Phase 2)

Paper 26012 · branch `revision/icait-2026` · seed 2026 · 1000 trials/chain ·
10000 benchmark iterations · results in `results/revised/`

This document describes what the corrected C1–C4 experiment does, how every
trial is generated and traced, what it proves, and what it explicitly does not
prove. It supersedes the previous harness, in which C1/C4 merely set the merchant
approval flag to `False` and never ran the L1 analyzer.

---

## 1. What changed

| Aspect | Previous (`experiments.run_effectiveness`) | Corrected (`scenarios` + `experiments`) |
|---|---|---|
| C1/C4 "attack" | `set_merchant_approval(..., False)` only | submits a Python mini-app carrying V1/V6 (C1) or V1/V6/V2/V3 (C4) to the **real L1 analyzer**; the gate decision comes from the analysis |
| L1 exercised | never | on every C1/C4 trial (and on C3 to detect V4) |
| C2 variation | random attacker id the ownership check ignores | varying attacker id **and** target owner id, a genuine IDOR attempt; plus a real response-minimisation check (V5) |
| C3 variation | random amount | varying tampered amount against a signed claim, plus real weak-crypto detection (V4) at onboarding |
| Traceability | none (aggregates only) | one `trials.csv` row per trial with input variation, indicators, decision, rejection reason, first blocking layer, and per-stage evidence |
| CI interpretation | over near-identical trials | over distinct, security-relevant inputs (see §4) |
| CCRS evidence | CCRS only | CCRS beside max, mean, capped-sum and sequential-product, plus a plausibility table |

## 2. Trial construction

Implementation: `src/mslm/scenarios.py`. For each chain and each index the
harness:

1. creates a fresh gateway (fresh key ring, replay store, audit log);
2. provisionally issues one valid signed token (a legitimate-looking credential);
3. runs **L1 onboarding** on a scenario-specific merchant submission via
   `MSLMGateway.onboard_merchant`, which calls `OnboardingAuditor.analyze`;
4. executes the chain-specific attack against the enforced layer;
5. records every stage (control, layer, decision, blocked?, reason, evidence).

Attack input variation per chain (all deterministic from `seed:chain:index:kind`):

| Chain | Indicators | Input variation | First blocking control |
|---|---|---|---|
| C1 | V1, V6 | unique `custom_auth_<i>` + hard-coded secret + `admin_refund_<i>` source | L1 analyzer → gate |
| C2 | V2, V5 | varying attacker id + target owner id; IDOR request; sensitive response payload | L2 ownership check (+ L2 minimisation) |
| C3 | V3, V4 | weak-crypto `receipt_hash_<i>` source; signed amount vs varying tampered amount | L3 signature/claim binding |
| C4 | V1, V6, V2, V3 | combined malicious submission (V1+V6+V2+V3 indicators) | L1 analyzer → gate |

Controls: each trial is paired with a legitimate control (clean source, valid
token, owner principal, untampered amount) that must be **accepted**.

## 3. Traceability schema (`results/revised/trials.csv`)

Columns: `trial_id, chain, kind, seed, index, indicators, expected_layer,
expected_outcome, outcome, first_blocking_layer, matched_expectation,
stage_count, controls, input_variation, stage_trace`.

`stage_trace` is a JSON array; each element has `control, layer, decision,
blocked, reason, evidence`. Examples:

- C1 attack: `L1.onboarding` deny with
  `evidence.rule_ids = [L1.AUTH.CUSTOM, L1.AUTH.HARDCODED_SECRET, L1.AUTHZ.MISSING]`
  and `vulnerability_ids=[V1,V6]`, then `L1.gate` deny.
- C2 attack: `L1.onboarding` approve; `L2.enforcement` deny
  (`resource ownership check failed`); `L2.minimization` sanitize
  (`cvv_present=false`, `password_present=false`, PAN masked).
- C3 attack: `L1.onboarding` approve with `V4` finding (`CCRS=5.9`); `L3.enforcement`
  deny (`claims do not match payment request`).
- C4 attack: `L1.onboarding` deny with `[V1,V2,V3,V6]`; `L1.gate` deny. No L2/L3
  stage is reached.

## 4. Corrected results (seed 2026, 1000 trials/chain)

Source: `results/revised/effectiveness.csv`.

| Chain | Blocked | Unexpected approvals | Controls accepted | First layer | Distinct attack inputs |
|---|---|---|---|---|---|
| C1 | 1000 | 0 | 1000 | L1 | 1000 |
| C2 | 1000 | 0 | 1000 | L2 | 1000 |
| C3 | 1000 | 0 | 1000 | L3 | 958 |
| C4 | 1000 | 0 | 1000 | L1 | 1000 |

C3 has 958 distinct inputs because tamper amounts are sampled from
`1..9999` and a few values repeat across indices — this collision is reported,
not hidden. The Wilson 95% lower bound is 99.617% for each chain.

## 5. What the corrected experiment proves

- The **L1 analyzer runs and reports the expected indicators** for C1, C4 and
  (for V4) C3; the gate decision is derived from the analysis, not hard-coded.
- The **L2 ownership and minimisation controls** reject a genuine IDOR attempt
  and remove/mask sensitive fields.
- The **L3 controls** reject a tampered amount against signed claims.
- Every attack trial is blocked at its **expected** layer and every matched
  legitimate control is accepted.
- Each of the 4,000 attack trials and 4,000 controls is individually
  traceable to the control that produced the decision.

## 6. What it does **not** prove

- It does not prove universal or production security effectiveness; the inputs
  are synthetic and the scenarios are the four encoded chains.
- It does not prove end-to-end **sequential** chain execution: C1 and C4 are
  stopped at L1, so the later steps are never reached. The short-circuit is
  recorded explicitly (`C4` has only L1 stages).
- It does not prove L1 detection completeness; L1 is a Python-AST heuristic.
- The confidence interval is a binomial interval over the sampled inputs; it is
  not an estimate of real-world attack success probability.

Recommended wording: *"Within the defined synthetic scenarios, MSLM blocked
every encoded trial at its expected first enforcement layer and accepted every
matched control."* Avoid "prevents all attacks".

## 7. Reproduction

```bash
PYTHONPATH=src python3 -m mslm.experiments \
  --iterations 1000 --benchmark-iterations 10000 --seed 2026 \
  --output results/revised
```

Outputs: `experiment.json`, `effectiveness.csv`, `performance.csv`, `ccrs.csv`,
`plausibility.csv`, `trials.csv`.
