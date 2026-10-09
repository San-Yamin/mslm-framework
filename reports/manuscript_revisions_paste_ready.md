# Paste-Ready Manuscript Revisions

Paper 26012 · keyed to the submission text · prepared 2026-10-09

Each block is **FIND** (exact text in the current manuscript) → **REPLACE**
(proposed text). `[AUTHOR: …]` marks a decision only the authors can finalize.
Nothing here invents results or evidence; proposed CVSS vectors are flagged as
proposals to be verified against the official FIRST.org calculator.

---

## A1. OWASP Juice Shop claim (Reviewer I.6)

> **Evidence update (2026-10-09):** 27 Juice Shop screenshots were located and
> reviewed (`reports/juice_shop_evidence_review.md`). They confirm the instance
> (`OWASP Juice Shop v20.0.0`, Node v25.6.0, `Express ^4.22.1`, 2026-06-17) and
> show several patterns observed, but **not** IDOR, **not** a complete attack
> chain, and **no** MSLM control. The replacements below are now evidence-limited
> rather than claims of successful reproduction. A human should visually confirm
> the OCR-derived readings before submission.
>
> **Author confirmations (2026-10-09):** both `sanyamin2005@gmail.com` and
> `demo@gmail.com` are author-created test accounts. The `ADMIN_TOKEN` local
> storage entry is **author-reported** as automatically generated; an independent
> check of the available Juice Shop v20.0.0 source and built frontend found **no**
> `ADMIN_TOKEN` key, so it must **not** be described as a confirmed default
> credential. No passwords or token values are reproduced in these reports.

### A1a. Abstract — FIND
> Selected vulnerability patterns were reproduced in a controlled OWASP Juice Shop
> v20.0.0 environment.

### A1a. Abstract — REPLACE
> Representative weakness patterns were observed in a local OWASP Juice Shop
> v20.0.0 instance, while the MSLM prototype and all defense experiments were
> evaluated in a separate synthetic Python test harness.

### A1b. §III.C — FIND
> Motivated by the anonymized industry report and controlled OWASP Juice Shop
> reproduction, this study defines six vulnerability classes for analysis and
> encodes their defensive conditions in the Python test harness (Table I).

### A1b. §III.C — REPLACE
> Motivated by the anonymized industry report and by representative weakness
> patterns observed in a local OWASP Juice Shop v20.0.0 instance, this study
> defines six vulnerability classes for analysis and encodes their defensive
> conditions in the Python test harness (Table I). The classes are mapped to
> explicit scenario assumptions, and the corresponding CVSS v3.1 vectors are
> listed in Table I; the vectors describe the modeled scenario rather than a
> scanned production application.

### A1c. §VII.A — FIND
> Selected vulnerability patterns were manually reproduced in a local OWASP Juice
> Shop v20.0.0 environment [11]. MSLM v0.2.0 was evaluated separately using Python
> 3.9.6 on macOS 15.6 arm64.

### A1c. §VII.A — REPLACE
> A local OWASP Juice Shop v20.0.0 instance (Node.js v25.6.0, `Express ^4.22.1`,
> `http://localhost:3000`, 2026-06-17) was examined only to observe representative
> weakness patterns: acceptance of a weak registration password; a login JWT whose
> decoded payload embedded the user's password hash; tokens present in browser
> local storage; over-broad unauthenticated product records from `/api/products`;
> and misconfigured response headers. Attempts to access `/api/users/{1,2,3}`
> without authorization returned `401`, so an IDOR pattern was **not** reproduced;
> a client-supplied `totalPrice` was accepted by `PUT /api/BasketItems/9`, but the
> resulting order total was not captured, so price manipulation is reported as an
> **attempt only**. No complete attack chain was reproduced in Juice Shop, and no
> MSLM control was exercised there. The MSLM v0.2.0 prototype and all defense
> experiments were evaluated separately using Python 3.9.6 on macOS 15.6 arm64.

### A1d. §VIII.C — FIND
> First, the OWASP Juice Shop reproduction and synthetic Python harness do not
> establish production-level external validity [11].

### A1d. §VIII.C — REPLACE
> First, the Juice Shop examination was observational and partial: IDOR attempts
> were rejected (`401`), price manipulation was not demonstrated end-to-end, no
> complete attack chain was reproduced, and no MSLM control was exercised in Juice
> Shop. Together with the synthetic Python harness, these results do not establish
> production-level external validity.

> **Note:** the screenshots are terminal/browser captures, not pinned artifacts
> (no container digest, compose file, or full request/response logs). If pinned
> artifacts are produced, the capture detail can be expanded; do not strengthen the
> claim beyond what the screenshots show.

---

## A2. Effectiveness and trial-generation wording (Reviewers I.3, I.4)

### A2a. §VII.A — FIND
> The evaluation included 54 automated tests, 1,000 seeded (seed 2026) attack
> trials and 1,000 matched legitimate controls per chain, and a 10,000-iteration
> local L2+L3 microbenchmark.

### A2a. §VII.A — REPLACE
> The evaluation included 80 automated tests, 1,000 seeded (seed 2026) attack
> trials and 1,000 matched legitimate controls per chain, and a 10,000-iteration
> local L2+L3 microbenchmark.

### A2b. §VII.D — INSERT after the first sentence
> Each trial is generated deterministically from the seed and a per-chain index.
> C1 and C4 vary the malicious merchant source (custom authentication, hard-coded
> secret, and missing-authorization indicators); C2 varies the attacker identity
> and the target owner identity to form genuine IDOR requests returning a
> sensitive response payload; C3 varies the tampered payment amount against a
> validly signed claim while exposing weak-cryptography indicators at onboarding.
> Every attack trial is paired with a matched legitimate control (clean source,
> valid token, correct owner, untampered amount). Because C1 and C4 are blocked by
> the L1 onboarding gate, their later stages are not reached; the short-circuit is
> recorded per trial rather than assumed. The reported interval is a binomial
> interval over the sampled synthetic inputs, not an estimate of real-world
> attack-success probability.

### A2c. §VII.D — FIND (last sentence)
> These findings apply only to the four encoded scenarios.

### A2c. §VII.D — REPLACE
> These findings apply only to the four encoded scenarios and the sampled synthetic
> inputs; they do not demonstrate general or production security effectiveness.

---

## A3. "Chained risk" semantics + plausibility gate (Reviewers I.1, III.1)

### A3. §IV.D — INSERT after the "Permutation invariance" paragraph
> Because CCRS is a function only of the CVSS multiset, two chains that share the
> same scores receive identical CCRS values even when their attack paths differ.
> Conversely, adding a weakness that is unreachable or irrelevant to the path
> still increases the score: a single 7.5 vulnerability yields CCRS 7.5, whereas
> adding an unrelated 5.9 weakness raises it to 8.975. To distinguish a set of
> related vulnerabilities from a plausible attack chain, this study requires a
> **chain-qualification** step before aggregation. Each step must declare (i) the
> prerequisite it depends on, (ii) the trust boundary it crosses, and (iii) the
> evidence supporting the transition. This plausibility assessment is
> analyst-declared transparency metadata, not an automated reachability engine; it
> makes the otherwise-implicit chain assumptions auditable and is exported with
> the experiment results.

---

## A4. Comparison with alternative aggregations (Reviewer I.2)

### A4. §VII.C — INSERT after the existing paragraph
> Table VI also reports the mean of the component CVSS scores and compares CCRS
> with the maximum CVSS, the mean CVSS, a capped sum, and the sequential all-steps
> product (the last answers a different, joint-progression question). For every
> chain, CCRS lies at or above the maximum and exceeds the mean, while remaining
> below the capped sum. Because no external ground truth is available, this is
> presented as mathematical behavior of the aggregation rather than evidence that
> CCRS is a more accurate predictor; empirical superiority is not claimed.

### A4b. Table VI — REPLACE the body with (recomputed after the V5 change)
| Chain | CVSS Max | CVSS Avg | CCRS | Capped Sum | Seq. Product | Δ vs Max | Observed Impact |
|---|---|---|---|---|---|---|---|
| C1 | 7.5 | 7.35 | 9.3 | 10.0 | 5.40 | +24.0% | Full account takeover |
| C2 | 6.5 | 6.50 | 8.775 | 10.0 | 4.225 | +35.0% | Payment data harvested |
| C3 | 8.1 | 7.00 | 9.221 | 10.0 | 4.779 | +13.84% | Fraudulent transactions |
| C4 | 8.1 | 7.325 | 9.95345 | 10.0 | 2.843 | +22.88% | Complete compromise |
| **Avg** | **7.55** | **7.0438** | **9.312363** | **10.0** | **4.312** | **+23.93%** | — |

Note: "Capped Sum" saturates at 10 for every chain; CCRS remains strictly below
it, showing CCRS is bounded while a capped sum is not discriminating. Seq.
Product = 10 × ∏(CVSSᵢ/10) (joint-progression reading).

### A4. Remove any comparative-superiority wording
> Check §I.B, §VII.C, and the Abstract for "more accurate"/"better predicts" and
> replace with "higher chain-aware prioritization" or "larger cumulative score".

---

## A5. CVSS vectors (Reviewer I.5)

### A5a. Table I — add a vector column
Proposed CVSS v3.1 vectors (**verify each base score with the official FIRST.org
calculator before submission**; see `reports/cvss_justification.md`):

| ID | Vulnerability | OWASP | Vector (proposed) | Base |
|---|---|---|---|---|
| V1 | Broken Authentication | A07:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| V2 | Insecure Direct Object Ref. | A01:2021 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| V3 | Client-Side Price Manip. | A03:2021 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| V4 | Weak Cryptographic Impl. | A02:2021 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 5.9 |
| V5 | Sensitive Data Exposure | A02:2021 | **unresolved — see A5b** | 6.2? |
| V6 | Missing Authorization | A01:2021 | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` | 7.2 |

Add a sentence after Table I:
> Base scores are derived from the vectors above under the stated scenario
> assumptions; they are scenario values, not scanned production findings.

### A5b. V5 — ADOPTED: 6.5
V5 was changed from 6.2 to **6.5** using the clean vector
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (authenticated, confidentiality-only, high
impact), which matches the "sensitive data exposure" scenario. No clean v3.1
vector yields 6.2 for this scenario. Applied in code:
`risk.py:PAPER_CHAINS["C2"]`, `l1.py:CVSS_BY_VULNERABILITY`, `scenarios.py`.
Tests and the experiment were re-run and pass.

Recomputed downstream values (Table VI in A4b):
- C2 CCRS = **8.775** (was 8.67); C2 amplification = **+35.0%** (was +33.38%)
- Table VI overall CCRS avg = **9.312363** (was 9.286); avg amplification = **23.93%** (was 23.53%)
- Recompute §VII.F sensitivity ranges for C2 (the ±0.5 band around the new score).

Table I V5 row becomes: vector `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, base 6.5.
**Verify all values with the official FIRST.org calculator before submission.**

---

## A6. L1 implementation scope (Reviewer III.2)

### A6. §VI.B — INSERT after "fails closed on syntax errors."
> The prototype analyzes Python source using the standard-library `ast` module.
> Production mini-app submissions are typically JavaScript/TypeScript; the same
> indicator rules would require a separate JS/TS front end that is not implemented
> or evaluated here. L1 should therefore be read as a language-limited research
> detector over Python submissions used to represent onboarding artifacts, not as
> a general mini-app scanner.

---

## A7. Performance reporting (Reviewer II / internal)

### A7. §VII.E — INSERT after the latency sentence
> Across repeated runs, p99 varied between approximately 17 and 33 microseconds;
> these figures should be read as order-of-magnitude microbenchmark results rather
> than stable constants.

---

## A8. Deployment cap definition (internal consistency)

### A8. §IV.F — FIND
> Raw values are retained for analysis, while the prototype optionally applies a
> deployment-policy cap of 9.8.

### A8. §IV.F — REPLACE
> Raw values are retained for analysis. The prototype optionally applies a
> deployment-policy cap of 9.8; this cap is a local operational choice, not part of
> the CCRS definition, and is applied only to the deployment score (for example,
> the raw CCRS of 9.95345 for C4 becomes 9.8 when capped). Raw and capped values
> are reported separately.

---

## A9. Test-count consistency (all sections)

The revised artifact contains **80** tests. Update every occurrence of "54":

| Location | FIND | REPLACE |
|---|---|---|
| Abstract | `comprised 54 automated tests` | `comprised 80 automated tests` |
| §I.B | `evaluated using 54 automated tests` | `evaluated using 80 automated tests` |
| §VII.A | `included 54 automated tests` | `included 80 automated tests` |
| §VII.B | `The 54 tests comprised 10 CCRS, 11 L1, 10 L2, 11 L3, 8 pipeline, and 4 experiment/evidence tests` | `The 80 tests comprised 21 CCRS/aggregation, 11 L1, 10 L2, 11 L3, 11 pipeline, and 16 experiment/evidence tests` |
| Conclusion | `passed 54 automated tests` | `passed 80 automated tests` |

### Table V — REPLACE with
| Component | Tests | Main Behavior Verified | Result |
|---|---|---|---|
| CCRS / Aggregation | 21 | C1–C4 scores, boundaries, invalid inputs, aggregation comparison, chain plausibility | 21/21 passed |
| L1 Onboarding | 11 | Code indicators, findings, merchant rejection | 11/11 passed |
| L2 API Security | 10 | Authentication, IDOR, isolation, minimization | 10/10 passed |
| L3 Payment Integrity | 11 | Signature, claims, expiry, replay, validation | 11/11 passed |
| Integrated Pipeline | 11 | Layer blocking, approval, token issuance, audit, onboarding | 11/11 passed |
| Experiment / Evidence | 16 | Determinism, layer, distribution, output files, trial variation, L1 execution | 16/16 passed |
| **Total** | **80** | Functional and integration behavior | **80/80 passed** |

---

## A10. Reference [11] (Juice Shop)

If Juice Shop is removed from the methodology and limitations, either:
- drop [11], or
- keep it only as a cited example of vulnerability encodings ("informed by public
  examples such as [11]"). Renumber subsequent references if dropped.

---

## Checklist

- [ ] Apply A1a–A1d (evidence-limited wording; screenshots are not pinned artifacts).
- [ ] Apply A2a–A2c.
- [ ] Apply A3 (chain qualification paragraph).
- [ ] Apply A4; remove superiority wording.
- [ ] Apply A5a; decide A5b; recompute downstream numbers if V5 changes.
- [ ] Apply A6.
- [ ] Apply A7.
- [ ] Apply A8.
- [ ] Apply A9 everywhere, including Table V.
- [ ] Apply A10.
- [ ] If V5 changed: update `PAPER_CHAINS`, re-run tests + experiment, re-save results.
