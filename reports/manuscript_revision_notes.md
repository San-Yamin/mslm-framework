# Manuscript Revision Notes (Phases 5–6)

Paper 26012 · "A Cumulative Chained Risk Metric for Securing FinTech Mini-App
Ecosystems" · prepared 2026-10-09

This file lists the manuscript claims that must change, with the evidence
behind each recommendation. Nothing here invents results, citations, dates,
vectors, screenshots, or test evidence.

## A. Claims that must change

### A1. OWASP Juice Shop reproduction — §VII-A and Abstract (Reviewer I.6)
- **Current:** "Selected vulnerability patterns were manually reproduced in a
  local OWASP Juice Shop v20.0.0 environment."
- **Problem:** No Juice Shop artifacts exist (no image digest, scripts, traces,
  logs). The project docs state this explicitly.
- **Recommended:** If artifacts cannot be produced, change to: *"The Python
  prototype was evaluated with synthetic controlled scenarios inspired by the
  documented vulnerability taxonomy; OWASP Juice Shop was not part of the
  reproducible artifact."* Remove Juice Shop from the Abstract unless artifacts
  are preserved.

### A2. Effectiveness wording — §VII-D and Abstract (Reviewers I.3, I.4)
- **Current:** "MSLM blocked every encoded attack at its expected first
  enforcement layer while accepting every matched control," and the CI framing.
- **Problem:** Previously C1/C4 trials only flipped the approval flag; C4's later
  steps never ran; C2's trials were effectively identical. The revised harness
  fixes this, but the manuscript must describe it honestly.
- **Recommended additions:**
  - Describe how each of the 1,000 trials is generated and varied (per chain).
  - State that C1/C4 are blocked at the L1 gate, so later layers are not reached
    in those trials (defense-in-depth is shown across chains, not within C4).
  - Describe the 95% interval as a binomial interval over the sampled synthetic
    inputs, not as real-world attack success probability.
  - Add: *"These results apply only to the four encoded scenarios."*

### A3. "Chained risk" semantics — §IV-B/§IV-D (Reviewers I.1, III.1)
- **Current:** CCRS is described as a chain metric; permutation invariance is
  noted in §IV-D.
- **Add explicitly:**
  - Two chains with the same CVSS multiset receive the same CCRS even if their
    attack paths differ.
  - Adding an unreachable or irrelevant vulnerability still raises CCRS
    (demonstrated in `tests/test_plausibility.py`; V1 only 7.5 → V1+unrelated
    V4 8.975).
  - CCRS does not encode order, prerequisites, reachability, or conditional
    dependence.
- **Add the plausibility gate:** before aggregation, require each step to declare
  a prerequisite, a crossed trust boundary, and supporting evidence
  (`reports/experiment_methodology.md`, `plausibility.csv`). State clearly that
  the gate is analyst-declared transparency metadata, not a reachability engine.

### A4. Comparison with other aggregations — §VII-C (Reviewer I.2)
- **Current:** only "CCRS > max CVSS" with amplification percentages.
- **Add:** comparison against maximum CVSS, mean CVSS, capped sum, and the
  sequential all-steps product (now emitted in `ccrs.csv`). Present it as
  *mathematical behaviour*, and state that empirical superiority is not claimed
  without external ground truth. Remove "more accurate" if present.

### A5. CVSS vectors — Table I / §III-C (Reviewer I.5)
- Add the full CVSS v3.1 vectors and assumptions (`reports/cvss_justification.md`).
- **RESOLVED: V5 re-derived 6.2 → 6.5** with vector
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. Downstream values updated in code and in
  Table VI (C2 CCRS 8.775; overall avg 9.312363). See paste-ready A5/A4b.

### A6. L1 scope — §VI-B / §VII-B (Reviewer III.2)
- **Current:** L1 framed as merchant onboarding analysis for a mini-app ecosystem.
- **Add:** L1 parses **Python AST only**; mini-app submissions are typically
  JavaScript/TypeScript; the same policy rules would need a JS/TS front end that
  is not implemented or evaluated. State the deployment limits this places on
  onboarding claims (see `docs/SECURITY_MODEL.md`).

### A7. Performance reporting — §VII-E
- Numbers match the preserved `results/experiment.json` (median 15.042 µs,
  p95 15.417, p99 17.334). Keep, but note run-to-run variance (fresh runs show
  p99 up to ~21–33 µs) and that this is a local microbenchmark, not end-to-end
  latency.

### A8. CCRS deployment cap — §IV-B/§IV-F, Table VI
- The manuscript refers to a 9.8 cap but §IV-B does not define it. §IV-F says the
  prototype "optionally applies a deployment-policy cap of 9.8". Define the cap
  explicitly where first used and separate raw CCRS from deployment-capped CCRS
  (raw C4 = 9.95345; capped = 9.8).

### A9. Repository-only issue (not manuscript)
- `README.md:8` refers to "*Quantifying the Unseen*", which is not this paper's
  title. Update the repository description.

## B. Numbers verified as already consistent (no change needed)

- Test-count breakdown vs Table V (10/11/10/11/8/4 = 54) is accurate.
- Original CCRS values (C1 9.30, C2 8.67, C3 9.221, C4 9.95345) and
  amplifications (24.0/33.38/13.84/22.88%, mean 23.53%) were internally consistent.
  **After the V5 revision** they become C2 **8.775** (+35.0%) and mean
  amplification **23.93%**.
- Original Table VI means (max 7.55, avg 7.006, CCRS 9.286) are internally
  consistent. **After the V5 revision**: avg **7.0438**, CCRS **9.312363**.
- Environment (Python 3.9.6, macOS 15.6 arm64) matches.
- Note: `docs/PAPER_EVIDENCE.md`'s remark that "average CCRS is not 9.91" is
  stale — the current manuscript already reports 9.286.

## C. Reviewer-response mapping

See `reports/reviewer_evidence_matrix.md` (post-revision status section) for the
comment-by-comment disposition, and `reports/experiment_methodology.md` for the
corrected method narrative that can be adapted into §VII.
