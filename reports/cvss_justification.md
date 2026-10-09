# CVSS v3.1 Justification Assessment (Phase 5)

Paper 26012 · reviewer comments I.5 (and III.1 indirectly) · audit date 2026-10-09

## 1. Finding: no vectors exist in the artifact

The repository contains **only scalar scores** (`src/mslm/l1.py:11-18`,
`risk.py:PAPER_CHAINS`). Neither the repository nor the manuscript supplies
CVSS v3.1 vectors, metric breakdowns, or a derivation. Reviewer I.5 is
therefore correct that the values are author-assigned. The manuscript already
concedes this in §III-C ("paper-assigned scenario values"), but the reviewer
asks for the vectors or a clear derivation.

## 2. Method used here

To assess whether the assigned values can be *justified* (not to recover them),
a CVSS v3.1 base-score calculator implementing the FIRST.org v3.1 specification
was run in the audit environment. It was sanity-checked against published values
(e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1 and `…/C:H/I:N/A:N` = 7.5 and
`…/UI:R/S:C/C:L/I:L/A:N` = 6.1). The calculator is **not** a project dependency
and no code from it is shipped.

The candidate vectors below are **proposed encodings for the revised manuscript,
not recovered from the original submission**. They must be reviewed, adopted or
replaced by the authors before publication. They are offered only to show
whether a valid v3.1 vector can yield each score under explicit assumptions.

## 3. Per-vulnerability assessment

| ID | Assigned | Scenario assumption | Candidate vector (PROPOSED) | Computed | Verdict |
|---|---|---|---|---|---|
| V1 Broken Authentication | 7.5 | Unauthenticated network attacker reads auth-protected data; no integrity effect modeled | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | Justifiable, but if account takeover (integrity) is modeled, the score would rise (e.g. C:H/I:H ⇒ 9.1). Must state the limited impact assumption. |
| V2 IDOR | 6.5 | Authenticated low-privilege attacker reads another user's object | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Justifiable. |
| V3 Client-side price manipulation | 8.1 | Authenticated user alters payment amount (integrity) with confidentiality impact | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 | Justifiable. |
| V4 Weak cryptographic implementation | 5.9 | Remote but high-complexity cryptographic break, confidentiality only | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 5.9 | Justifiable. |
| V5 Sensitive data exposure | 6.2 | Learner data returned without minimisation | **no clean vector found** | — | **Not readily justifiable.** With `S:U,AV:N`, a 6.2 requires the unusual combination `AC:H/PR:H` plus multi-letter impact (e.g. `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:L`), which does not match "sensitive data exposure". 6.2 is an uncommon CVSS value; nearby natural outcomes are 6.5. **The authors must either publish the exact vector used or re-derive this score.** |
| V6 Missing Authorization | 7.2 | Unauthenticated user crosses a tenant trust boundary (scope change) | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` | 7.2 | Justifiable via scope change. (An `S:U` route exists only with `PR:H`, less consistent with the scenario.) |

Summary: **5 of 6 assigned scores can be produced by plausible, valid v3.1
vectors. V5 = 6.2 cannot be justified without an idiosyncratic vector and should
be corrected or explicitly documented.** No inputs were manipulated to match the
paper.

## 4. Required actions for the manuscript

1. Add a column or appendix that lists, for each V1–V6, the full CVSS v3.1
   vector, the scope/impact assumptions, and the computed base score.
2. Re-derive V5 (or justify 6.2 with a stated vector and rationale).
3. Ensure every affected number downstream (CCRS, amplification, Table VI,
   sensitivity ranges) is recomputed if any score changes.
4. Keep §III-C's caveat that the scores are scenario values, and state that the
   vectors describe the *modeled* scenario, not a scanned production app.

## 5. Juice Shop external evidence (reviewer I.6)

**No OWASP Juice Shop reproduction artifacts exist** in the repository:
no container digest, test scripts, Burp exports, traces, or logs. The project's
own documentation says so (`docs/PAPER_EVIDENCE.md:43-57`,
`docs/TESTING_GUIDE_FOR_PROFESSOR.md:225-229`).

Therefore the manuscript claim in §VII-A ("Selected vulnerability patterns were
manually reproduced in a local OWASP Juice Shop v20.0.0 environment") is
**unsupported by the artifact**. Per instruction, this is flagged for correction
rather than back-filled with invented results. See
`reports/manuscript_revision_notes.md` for the recommended wording.

## 6. Reproducibility note

The candidate-vector check is reproducible with a standard CVSS v3.1
implementation; the audit calculator is not part of the repo. Any vector adopted
in the manuscript should be independently verified against the official FIRST.org
CVSS v3.1 calculator before submission.
