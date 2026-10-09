# Reviewer Responses — for the ICAIT 2026 Revision Manuscript Improvement Form

Paper ID: 26012
Title: A Cumulative Chained Risk Metric for Securing FinTech Mini-App Ecosystems
Prepared: 2026-10-09

Paste each row into Section 2 of the form. "Location" cites the revision
artifact, not a page number (page numbers are set when the manuscript is
re-typeset). Items marked **[AUTHOR DECISION]** require the author to confirm the
wording or produce external evidence.

---

## Reviewer I

**1. "Chained risk" is misleading: CCRS is permutation invariant and ignores
order, prerequisites, reachability, dependency.**
Action: Added an explicit chain-plausibility assessment (`assess_chain_plausibility`)
that requires each step to declare a prerequisite, a crossed trust boundary, and
supporting evidence before a set is aggregated; added tests showing two chains
with equal CVSS receive equal CCRS regardless of path and that an unreachable or
irrelevant weakness still raises the score; documented that CCRS encodes set
severity, not sequence.
Location: `src/mslm/risk.py`, `tests/test_plausibility.py`,
`results/revised/plausibility.csv`, manuscript §IV-B/§IV-D.

**2. CCRS > max CVSS is expected from the formula; add stronger comparison.**
Action: Added comparison against maximum CVSS, mean CVSS, capped sum, and the
sequential all-steps product; results emitted per chain and presented as
mathematical behaviour, with no claim of empirical superiority.
Location: `src/mslm/risk.py`, `results/revised/ccrs.csv`, manuscript §VII-C.

**3. Do not present 4,000 synthetic blocks as general security effectiveness.**
Action: Limited every claim to the four encoded scenarios; recorded the scope in
the experiment limitations and documentation; no "prevents all attacks" language.
Location: `src/mslm/experiments.py`, `reports/experiment_methodology.md` §6,
manuscript §VII-D.

**4. Explain how 1,000 trials per chain are generated and how they differ.**
Action: Rewrote the harness so each trial records its input variation, indicators,
per-stage decision, reason, and first blocking layer; variation is now
security-relevant (unique malicious submissions for C1/C4, varying IDOR
attacker/owner pairs for C2, varying tampered amounts for C3). Row count and
distinct-input counts are reported honestly (C3 = 958 distinct).
Location: `src/mslm/scenarios.py`, `results/revised/trials.csv`,
`results/revised/effectiveness.csv`, `reports/experiment_methodology.md`.

**5. Provide CVSS vectors or derivation.**
Action: Assessed each assigned score against valid CVSS v3.1 vectors. Five of six
were already justifiable; **V5 was re-derived from 6.2 to 6.5** with the vector
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (no clean vector yields 6.2 for sensitive
data exposure). All downstream values (C2 CCRS 8.775, Table VI means) were
recomputed. No vectors were fabricated.
Location: `reports/cvss_justification.md`, `reports/manuscript_revisions_paste_ready.md` A5/A4b.

**6. Clarify the relationship between Juice Shop and the Python prototype.**
Action: Located and reviewed 27 Juice Shop screenshots (OWASP Juice Shop v20.0.0,
Node v25.6.0, `Express ^4.22.1`, 2026-06-17). Verified reproduced patterns:
weak-password registration accepted, a login JWT embedding the user's password
hash, tokens in browser local storage, over-broad unauthenticated
`/api/products`, and misconfigured response headers. Verified **failed** attempts:
IDOR requests to `/api/users/{1,2,3}` all returned `401`; price-tampering to
`PUT /api/BasketItems/9` was accepted at the API but the final charge is not
shown. No complete attack chain and **no MSLM control** was exercised in Juice
Shop. §VII-A, the Abstract, §III.C and §VIII.C were rewritten to separate the
Juice Shop pattern examination from the Python-only MSLM evaluation.
Author confirmations recorded: both `sanyamin2005@gmail.com` and
`demo@gmail.com` are author-created test accounts; the `ADMIN_TOKEN` local
storage entry is reported to be generated automatically by the application.
Independent check: the available Juice Shop v20.0.0 source and built frontend
contain **no** `ADMIN_TOKEN` key and no network capture shows its creation, so
automatic generation remains an **author report only** and is not presented as a
confirmed default credential. No passwords or token values are disclosed.
Location: `reports/juice_shop_evidence_review.md` §0a/§7,
`manuscript_revisions_paste_ready.md` A1.

## Reviewer II

**1. Add theory; use established terminology.**
Action: Terminology standardised to "Mini-App Ecosystem Security" / "FinTech
security frameworks" / "a typical FinTech mini-app ecosystem". **[AUTHOR DECISION]**
section-level editorial pass.
Location: manuscript (drafting); README.

**2. Explain how to map to merchant onboarding, control API security, and prove
payment integrity.**
Action: Provided a code-to-control mapping: L1 = onboarding AST analysis + gate;
L2 = deny-by-default RBAC + ownership + merchant isolation + response
minimisation; L3 = HMAC-SHA256 claim binding + expiry + nonce replay + rotation.
Each is exercised by tests and by the trials.
Location: `reports/reviewer_evidence_matrix.md`, `reports/experiment_methodology.md`,
`tests/test_{l1,l2,l3,pipeline}.py`, manuscript §VI.

**3. Explain limitations from your own experience.**
Action: Documented specific, experienced limitations (Python-AST scope, in-memory
state, microbenchmark excludes network/TLS/DB), not generic caveats.
Location: `docs/SECURITY_MODEL.md`, `reports/experiment_methodology.md` §6.

**4. Clearly describe how MSLM secures mini-app ecosystems.**
Action: Added an end-to-end description tying the layered controls to the four
scenarios and their first blocking layers.
Location: `reports/experiment_methodology.md`, `docs/TESTING_GUIDE_FOR_PROFESSOR.md`.

## Reviewer III

**1. Explain how vulnerability sets qualify as attack chains; define plausibility;
state equal-CVSS/equal-CCRS; discuss unreachable/irrelevant weaknesses.**
Action: Added the plausibility gate (prerequisites, trust boundaries, evidence)
and tests for permutation invariance and unreachable-vulnerability inflation.
Location: `src/mslm/risk.py`, `tests/test_plausibility.py`,
`results/revised/plausibility.csv`, manuscript §IV.

**2. Clarify implementation relevance to mini apps (L1 parses Python AST).**
Action: Documented that L1 analyses Python via `ast` only, how it relates to an
onboarding submission, and the deployment limits; stated the JS/TS front end is
future work and no corpus precision/recall is claimed.
Location: `docs/SECURITY_MODEL.md` ("L1 language scope and mini-app
representation"), manuscript §VI-B, README.

---

## Summary of major improvements (form Section 3)

- Corrected methodology: L1 analyzer now actually runs; C4 short-circuit recorded;
  per-trial traceability added.
- New evidence outputs: `plausibility.csv`, `trials.csv`, aggregation comparison.
- CCRS limitations documented with tests; L1 language scope documented.
- Reproducible baseline (`results/baseline/`) and revised (`results/revised/`) runs
  with environment and commit provenance.
- Test suite expanded 54 → 80, all passing.

## Items requiring author action

1. Publish CVSS v3.1 vectors; re-derive V5.
2. Record author confirmation already received: both test accounts are
   author-created; `ADMIN_TOKEN` auto-generation is **author-reported only** and
   must not be described as a confirmed default credential (see
   `reports/juice_shop_evidence_review.md` §0a/§7). Apply the evidence-limited
   Juice Shop wording (A1 in `reports/manuscript_revisions_paste_ready.md`).
3. Apply wording changes A1–A10 from `reports/manuscript_revisions_paste_ready.md`.
