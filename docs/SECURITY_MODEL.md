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

