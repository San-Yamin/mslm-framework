# MSLM Testing Guide and Professor Explanation

This guide explains how to test the Mini-App Security Layer Model (MSLM), how
to interpret the results, and how to present the project accurately.

## 1. The project in one sentence

MSLM is a three-layer security framework that screens risky merchant code,
enforces API authorization, and cryptographically protects payment details.

## 2. What each layer tests

| Layer | Purpose | Main threats |
|---|---|---|
| L1 — Onboarding audit | Examines merchant Python code before approval | V1 broken authentication, V4 weak cryptography, and indicators for V2–V6 |
| L2 — API security | Enforces identity, permissions, ownership and response minimization | V2 IDOR, V5 sensitive-data exposure, V6 missing authorization |
| L3 — Runtime gateway | Verifies signed, expiring, single-use payment claims | V3 price manipulation, token forgery and replay |

The layers provide defense in depth. A request must pass every applicable
layer; passing one layer does not bypass the others.

## 3. Requirements

- Python 3.9 or newer
- A terminal
- No third-party package is required for the core tests

From the project directory:

```bash
cd "/Users/sanyamin/Documents/My Paper Journey/mslm_framework"
```

## 4. Run the automated test suite

```bash
PYTHONPYCACHEPREFIX=/tmp/mslm-pycache \
python3 -m unittest discover -s tests -v
```

Expected final output:

```text
Ran 54 tests

OK
```

`OK` means all defined test cases passed. It does not prove that the framework
prevents every possible attack.

### What the 54 tests cover

- CCRS formula, caps, severity boundaries and invalid inputs
- L1 AST-based detection and stable finding identifiers
- L2 permissions, ownership, merchant isolation and recursive data masking
- L3 signature integrity, claim binding, expiry, replay prevention and key rotation
- Complete L1/L2/L3 payment decisions and audit events
- Deterministic experiment generation and machine-readable result files

## 5. Run the controlled evaluation

Use a fixed seed so another researcher can reproduce the same attack variations:

```bash
PYTHONPATH=src PYTHONPYCACHEPREFIX=/tmp/mslm-pycache \
python3 -m mslm.experiments \
  --iterations 1000 \
  --benchmark-iterations 10000 \
  --seed 2026 \
  --output results
```

This performs:

- 1,000 controlled trials for each of C1, C2, C3 and C4
- one legitimate negative control alongside each attack trial
- 10,000 local L2+L3 verification measurements
- CCRS calculation for all four paper chains

Generated evidence:

| File | Contents |
|---|---|
| `results/experiment.json` | Complete run parameters, environment, results and limitations |
| `results/effectiveness.csv` | Per-chain blocking and legitimate-control results |
| `results/performance.csv` | Mean, median, p95 and p99 latency |
| `results/ccrs.csv` | CVSS inputs, raw CCRS, capped score and amplification |

Keep `experiment.json` with the paper artifacts because it records the Python
version, operating system, seed and iteration counts.

## 6. How to interpret effectiveness

For each chain, report:

- number of attack trials;
- number blocked;
- unexpected approvals;
- expected first blocking layer;
- legitimate controls accepted;
- observed block rate;
- 95% confidence interval.

Example interpretation:

> MSLM was evaluated in 1,000 synthetic controlled trials per attack chain.
> All encoded C1–C4 attempts were blocked at their expected first enforcement
> layer, while all matched legitimate controls were accepted. The observed
> block rate was 100% in these defined scenarios, with a 95% Wilson lower bound
> of approximately 99.62%.

Do not say:

> MSLM proves 100% prevention of all attacks.

The experiment tests defined implementations of four attack chains. Unknown
attacks and real production conditions are outside its current scope.

## 7. How to interpret performance

Use median, p95 and p99 latency. Do not rely only on the mean.

The bundled benchmark measures local Python authorization and token
verification. It excludes:

- network and TLS latency;
- database latency;
- distributed replay-store latency;
- container and API-server overhead;
- real payment-processor latency.

Therefore, describe it as a **local microbenchmark**, not end-to-end payment
performance. Run it several times on the exact machine reported in the paper.

## 8. Demonstration plan for a professor

A concise demonstration can take five minutes.

### Step 1 — Explain the problem

“CVSS scores vulnerabilities individually. My research asks how we should
prioritize risk when weaknesses occur together in an attack path.”

### Step 2 — Explain CCRS carefully

“CCRS uses cumulative-complement aggregation:
`1 - product(1 - CVSS/10)`. It increases monotonically as vulnerabilities are
added. I use it as a risk-prioritization metric, not as a proven probability
that a sequential attack succeeds.”

### Step 3 — Explain the three defenses

“L1 screens merchant code before onboarding. L2 enforces authentication,
authorization, ownership and safe responses. L3 signs the merchant, user,
order, amount, currency, time window and nonce, then prevents reuse.”

### Step 4 — Run the tests

Show the command and the `Ran 54 tests — OK` result. Open one representative
test for each layer:

- `tests/test_l1.py`: risky merchant code is rejected
- `tests/test_l2.py`: an IDOR attempt is denied
- `tests/test_l3.py`: price tampering and replay are denied
- `tests/test_pipeline.py`: the complete layered decision

### Step 5 — Show experiment evidence

Open `results/experiment.json` and show:

- fixed seed and iteration count;
- attack blocking results;
- legitimate controls;
- confidence intervals;
- latency distribution;
- explicitly recorded limitations.

## 9. Questions a professor may ask

### Why not use only CVSS?

CVSS describes individual vulnerability severity. CCRS is intended to flag
sets of vulnerabilities whose combined presence deserves higher remediation
priority. Empirical comparison with real outcomes is still required to
establish whether CCRS predicts risk better.

### Is CCRS mathematically the probability of a sequential chain?

No. The complement formula represents a union probability only if the inputs
are calibrated independent probabilities. CVSS scores are severity measures,
not probabilities. The implementation and documentation state this limitation.

### Why use integer amounts?

Binary floating-point values can represent currency inconsistently. MSLM signs
integer minor units, such as 9,999 cents for USD 99.99, so signing and
verification use an exact canonical value.

### How is replay prevented?

Every token contains a random nonce and expiry. After successful verification,
the nonce is atomically consumed. A second use is rejected. The research
version uses an in-memory store; production requires a shared durable atomic
store.

### Can an attacker change the user or order but keep the token?

No. Merchant ID, user ID, order ID, amount, currency, timestamps, nonce and key
ID are all included in the signed canonical claims.

### Is L1 a complete vulnerability scanner?

No. It is an explainable AST-based research detector for known indicators. It
does not guarantee that arbitrary merchant code is secure. A larger labeled
corpus is needed to measure precision and recall.

### Is this production-ready?

No. It is a strengthened and reproducible research prototype. Production use
would require an identity provider, KMS/HSM, distributed replay database,
durable audit system, migrations, rate limiting, monitoring and external
security assessment.

### Has OWASP Juice Shop been tested?

Not by the bundled synthetic experiment. Juice Shop claims should be included
only after preserving the container digest, attack scripts, traces, logs and
baseline-versus-defended results from a real isolated test run.

## 10. Testing checklist before submitting the paper

- [ ] All 54 automated tests pass
- [ ] Exact test command is recorded
- [ ] Controlled experiment is rerun with fixed parameters
- [ ] `experiment.json` is preserved
- [ ] Legitimate negative controls are reported
- [ ] Confidence intervals are reported
- [ ] Median, p95 and p99 latency are reported
- [ ] Hardware, OS and Python version are reported
- [ ] Synthetic results are not described as Juice Shop results
- [ ] The CCRS mathematical limitation is acknowledged
- [ ] Average CCRS and amplification values are recalculated from generated data
- [ ] Claims use “observed in defined trials,” not universal proof

## 11. Recommended paper wording

> We implemented MSLM as a reproducible Python research prototype with three
> independently testable enforcement layers. The implementation was validated
> using 54 automated tests covering CCRS computation, onboarding analysis,
> authorization and ownership enforcement, response minimization, signed
> payment claims, expiry, key rotation, and replay prevention. A seeded
> synthetic evaluation executed each encoded attack chain alongside matched
> legitimate controls. Results describe the behavior of the defined test
> scenarios and do not imply universal prevention or production readiness.

