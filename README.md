# MSLM Framework

[![Tests](https://github.com/San-Yamin/mslm-framework/actions/workflows/tests.yml/badge.svg)](https://github.com/San-Yamin/mslm-framework/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This repository is a clean, reproducible implementation of the Mini-App
Security Layer Model (MSLM) described in *Quantifying the Unseen*. It is a
research prototype: it is suitable for controlled experiments and paper
evaluation, but it is not represented as a production payment gateway.

## Research contribution

MSLM combines two complementary ideas:

1. **Cumulative Chained Risk Score (CCRS)** prioritises the set of
   vulnerabilities associated with an attack chain on a bounded 0–10 scale.
2. **Mini-App Security Layer Model (MSLM)** applies controls at merchant
   onboarding (L1), API authorization and data minimisation (L2), and runtime
   payment-integrity enforcement (L3).

The repository evaluates four encoded attack-chain scenarios (C1–C4). It
contains 54 automated tests plus a deterministic experiment harness that pairs
each attack trial with a legitimate control. These results establish functional
feasibility within the defined experimental scope; they do not establish
universal real-world effectiveness or production readiness.

## What is implemented

- **CCRS research metric:** validated inputs, explicit assumptions, severity
  classification, and CVSS comparison.
- **L1 onboarding:** Python AST-based rules for V1–V6 indicators, stable
  finding identifiers, deduplication, and a CCRS deployment gate.
- **L2 API security:** authenticated principals, deny-by-default RBAC,
  ownership checks, recursive response minimisation, and audit events.
- **L3 gateway:** canonical integer monetary amounts, HMAC-SHA256 tokens bound
  to merchant, user, order, amount, currency, time window, nonce and key ID;
  constant-time verification; key rotation; and atomic single-use replay
  protection.
- **Evaluation harness:** repeatable attack-chain trials and latency
  benchmarks producing JSON and CSV evidence for Sections VII-C and VII-D.

## Reproduce

The core and test suite use only the Python standard library.

```bash
git clone https://github.com/San-Yamin/mslm-framework.git
cd mslm-framework
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m mslm.experiments \
  --iterations 1000 \
  --benchmark-iterations 10000 \
  --seed 2026 \
  --output results
```

Expected functional result: `Ran 54 tests` followed by `OK`. The experiment
then writes `experiment.json`, `ccrs.csv`, `effectiveness.csv`, and
`performance.csv` to `results/`.

## Repository guide

- `src/mslm/risk.py` — CCRS calculation and severity classification
- `src/mslm/l1.py` — explainable onboarding analysis and deployment gate
- `src/mslm/l2.py` — authorization, isolation, and response minimisation
- `src/mslm/l3.py` — signed payment claims and replay prevention
- `src/mslm/pipeline.py` — integrated enforcement path and audit decisions
- `src/mslm/experiments.py` — deterministic trials and evidence export
- `tests/` — 54 unit and integration tests
- `docs/` — security assumptions, evidence interpretation, and demonstration guide

Run the experiment on the machine and configuration that will be reported in
the paper. Do not copy sample or previous-run values into the paper without
executing the command and preserving its generated metadata.

## Research boundaries

CCRS uses `1 - product(1 - CVSS/10)`. This is a cumulative complement
aggregation. CVSS base scores are severity scores, not empirically calibrated
exploit probabilities, and the formula does not by itself model the joint
success probability of a strictly sequential chain. The paper should describe
CCRS as a prioritisation metric and validate it empirically before making
probability or predictive-accuracy claims.

See [docs/PAPER_EVIDENCE.md](docs/PAPER_EVIDENCE.md) for paper-ready reporting
guidance and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for assumptions.

## Citation

If this artifact supports academic work, cite the accompanying paper and see
[`CITATION.cff`](CITATION.cff) for repository metadata.

## Security and responsible use

This project is intended only for authorized research, education, and defensive
testing. See [`SECURITY.md`](SECURITY.md) for reporting guidance and deployment
limitations.
