# Security model and boundaries

## Trust boundaries

- Merchant operators authenticate independently from end users.
- L1 approval is a prerequisite, not proof that an application is vulnerability-free.
- L2 derives identity and role from a trusted authentication layer. Request parameters
  must never determine the caller's role.
- L3 assumes merchant HMAC keys remain server-side and gateway-verifiable.
- Prices use integer minor units; currency and order identity are signed.

## Layer guarantees

| Layer | Enforced property | Does not guarantee |
|---|---|---|
| L1 | Known Python indicators are reported and gated | Complete vulnerability detection |
| L2 | Deny-by-default permissions and ownership | Authentication provider correctness |
| L3 | Integrity, context binding, expiry, single use | Merchant business-logic correctness |

## L1 language scope and mini-app representation

L1 parses **Python source** with the standard-library `ast` module and applies
explainable indicator rules (`src/mslm/l1.py`). It does not parse JavaScript,
TypeScript, WXML/WXSS, WebAssembly, or packaged mini-app bundles. This is a
deliberate research simplification with the following consequences:

- **What is analysed.** A single Python module string submitted for onboarding.
  Rules detect: custom login handlers (V1), hard-coded authentication literals
  (V1), sensitive handlers without a visible authorization call (V6), weak
  primitives (`hashlib.md5`, `hashlib.sha1`, `random.*`) (V4), client-supplied
  price reads (V3), direct object references (V2), and bulk serialisation (V5).
- **Relation to a real mini-app submission.** In a production platform the
  onboarding pipeline would receive a packaged JS/TS bundle. L1 as implemented
  is best understood as a *front-end-agnostic policy core*: the same rule
  expressions could be applied to a JS/TS AST (or to a translated
  intermediate representation), but that translation layer is **not**
  implemented or evaluated here.
- **Deployment limits.** Precision/recall on a labelled mini-app corpus are
  unknown; there is no confidence scoring; rule hits are indicators, not
  confirmed vulnerabilities; and findings are deduplicated by `(rule, line)`,
  which assumes the submission preserves line structure.
- **Claim boundary.** The manuscript must not state or imply that L1 scans
  production JavaScript/TypeScript mini-apps. It should say L1 is a
  Python-AST prototype detector used to demonstrate the onboarding gate, and
  that adapting it to mini-app languages is future work.

## Production substitutions

The experiment uses an in-memory key ring, replay store, approval registry and audit
log. Production deployment requires an HSM/KMS, shared atomic replay database,
durable approval service, immutable audit sink, authenticated transport, rate
limits, monitoring, database transactions and incident-response procedures.

## CCRS interpretation

`1 - product(1 - score/10)` is monotonic and useful as a cumulative severity
aggregator. It equals a union probability only when inputs are calibrated
probabilities and independence holds. CVSS base scores do not meet that condition
by definition. For a strictly sequential chain whose steps must all succeed, the
independent joint probability would use a product of step probabilities.

The framework preserves the paper's formula but labels its assumption. A stronger
paper should describe CCRS as a risk-prioritisation score and assess construct,
criterion and predictive validity against baselines.

