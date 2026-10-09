"""Traceable C1-C4 attack-chain scenario construction.

Each scenario builds a per-trial record that names the input variation, the
vulnerability indicators under test, every security-control stage, the control
decision, the rejection reason, and the first blocking layer. The L1 analyzer is
actually executed for onboarding; it is never replaced by a manual flag flip.
"""

import random
from dataclasses import dataclass
from typing import Dict, List, Mapping, Tuple

from .audit import AuditLog
from .l1 import OnboardingAuditor
from .l2 import Principal, Role, minimize_response
from .l3 import KeyRing, PriceTokenService, ReplayStore
from .pipeline import MSLMGateway, TransactionRequest
from .risk import ChainStep

MERCHANT_ID = "merchant-1"
BASE_AMOUNT_MINOR = 10_000
BASE_TIME = 1_800_000_000

# Chain -> vulnerability identifiers claimed by the manuscript.
CHAIN_INDICATORS: Mapping[str, Tuple[str, ...]] = {
    "C1": ("V1", "V6"),
    "C2": ("V2", "V5"),
    "C3": ("V3", "V4"),
    "C4": ("V1", "V6", "V2", "V3"),
}

# Chain -> expected first MSLM enforcement layer (manuscript Table III).
CHAIN_EXPECTED_LAYER: Mapping[str, str] = {
    "C1": "L1",
    "C2": "L2",
    "C3": "L3",
    "C4": "L1",
}


@dataclass(frozen=True)
class Stage:
    control: str
    layer: str
    decision: str
    blocked: bool
    reason: str
    evidence: Dict[str, object]

    def as_dict(self) -> Dict[str, object]:
        return {
            "control": self.control,
            "layer": self.layer,
            "decision": self.decision,
            "blocked": self.blocked,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Trial:
    trial_id: str
    chain: str
    kind: str
    seed: int
    index: int
    indicators: Tuple[str, ...]
    expected_layer: str
    expected_outcome: str
    outcome: str
    first_blocking_layer: str
    matched_expectation: bool
    input_variation: Dict[str, object]
    stages: Tuple[Stage, ...]

    def as_row(self) -> Dict[str, object]:
        return {
            "trial_id": self.trial_id,
            "chain": self.chain,
            "kind": self.kind,
            "seed": self.seed,
            "index": self.index,
            "indicators": "|".join(self.indicators),
            "expected_layer": self.expected_layer,
            "expected_outcome": self.expected_outcome,
            "outcome": self.outcome,
            "first_blocking_layer": self.first_blocking_layer,
            "matched_expectation": self.matched_expectation,
            "stage_count": len(self.stages),
            "controls": "|".join(stage.control for stage in self.stages),
            "input_variation": _canonical(self.input_variation),
            "stage_trace": _canonical([stage.as_dict() for stage in self.stages]),
        }


def _canonical(value: object) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _new_gateway() -> MSLMGateway:
    keys = KeyRing()
    keys.add(MERCHANT_ID, "key-1", b"k" * 32, active=True)
    return MSLMGateway(PriceTokenService(keys, ReplayStore()), AuditLog(), OnboardingAuditor())


def _rng(seed: int, chain: str, index: int, kind: str) -> random.Random:
    return random.Random(f"{seed}:{chain}:{index}:{kind}")


# ---------------------------------------------------------------------------
# Merchant submission templates (Python, deliberately minimal and explainable)
# ---------------------------------------------------------------------------

def malicious_source_c1(index: int, token: str) -> str:
    return (
        "def custom_auth_{i}(request):\n"
        "    submitted = request['password']\n"
        "    return submitted == 'secret-{t}'\n"
        "\n"
        "def admin_refund_{i}(order):\n"
        "    return issue_refund(order)\n"
    ).format(i=index, t=token)


def malicious_source_c4(index: int, token: str) -> str:
    return (
        "def custom_auth_{i}(request):\n"
        "    submitted = request['password']\n"
        "    return submitted == 'secret-{t}'\n"
        "\n"
        "def admin_refund_{i}(order):\n"
        "    return issue_refund(order)\n"
        "\n"
        "def fetch_transaction_{i}(payload):\n"
        "    return payload['transaction_id']\n"
        "\n"
        "def charge_{i}(request):\n"
        "    amount = request['amount']\n"
        "    return amount\n"
    ).format(i=index, t=token)


def weak_crypto_source_c3(index: int) -> str:
    return (
        "def receipt_hash_{i}(payload):\n"
        "    return hashlib.md5(payload).hexdigest()\n"
    ).format(i=index)


def clean_source(index: int) -> str:
    return (
        "def health_{i}():\n"
        "    status = 'ok'\n"
        "    return status\n"
    ).format(i=index)


# ---------------------------------------------------------------------------
# Declared plausibility metadata (Phase 3)
# ---------------------------------------------------------------------------

CHAIN_STEPS: Mapping[str, Tuple[ChainStep, ...]] = {
    "C1": (
        ChainStep(
            "V1", 7.5,
            "attacker can reach the mini-app custom login handler",
            "user -> merchant mini-app",
            "tests/test_l1.py::test_custom_auth_detected; tests/test_scenarios.py",
        ),
        ChainStep(
            "V6", 7.2,
            "attacker holds a session that reaches a sensitive handler",
            "merchant mini-app -> backend service",
            "tests/test_l1.py::test_sensitive_admin_without_authorization_detected",
        ),
    ),
    "C2": (
        ChainStep(
            "V2", 6.5,
            "attacker can enumerate a victim-owned object reference",
            "user -> merchant API",
            "tests/test_l2.py::test_idor_denied; tests/test_pipeline.py::test_l2_blocks_idor",
        ),
        ChainStep(
            "V5", 6.5,
            "victim object is returned through a shared response path",
            "merchant API -> client",
            "tests/test_l2.py::test_pan_masked_and_cvv_removed",
        ),
    ),
    "C3": (
        ChainStep(
            "V3", 8.1,
            "attacker can alter the client-supplied payment amount before signing",
            "client -> merchant gateway",
            "tests/test_pipeline.py::test_l3_blocks_price_tampering",
        ),
        ChainStep(
            "V4", 5.9,
            "merchant integrity helper relies on a weak digest",
            "merchant mini-app -> integrity check",
            "tests/test_l1.py::test_weak_crypto_calls_detected",
        ),
    ),
    "C4": (
        ChainStep(
            "V1", 7.5,
            "attacker can reach the custom login handler",
            "user -> merchant mini-app",
            "tests/test_l1.py::test_custom_auth_detected",
        ),
        ChainStep(
            "V6", 7.2,
            "session reaches a sensitive handler without authorization",
            "merchant mini-app -> backend",
            "tests/test_l1.py::test_sensitive_admin_without_authorization_detected",
        ),
        ChainStep(
            "V2", 6.5,
            "attacker enumerates a victim object reference",
            "user -> merchant API",
            "tests/test_l2.py::test_idor_denied",
        ),
        ChainStep(
            "V3", 8.1,
            "attacker alters the payment amount",
            "client -> merchant gateway",
            "tests/test_l3.py::test_each_bound_claim_is_enforced",
        ),
    ),
}


# ---------------------------------------------------------------------------
# Trial construction
# ---------------------------------------------------------------------------

def _base_context(gateway: MSLMGateway, index: int) -> Tuple[Principal, object, str, int]:
    now = BASE_TIME + index
    merchant = Principal("merchant-operator", Role.MERCHANT, MERCHANT_ID)
    gateway.set_merchant_approval(MERCHANT_ID, True)
    claims, signature = gateway.issue_token(
        merchant,
        merchant_id=MERCHANT_ID,
        user_id="user-victim",
        order_id=f"order-{index}",
        amount_minor=BASE_AMOUNT_MINOR,
        currency="USD",
        now=now,
    )
    return merchant, claims, signature, now


def _onboarding_stage(decision) -> Stage:
    if not decision.findings:
        reason = "no findings"
    else:
        ccrs = None if decision.risk is None else decision.risk.raw_score
        indicators = ",".join(sorted({f.vulnerability_id for f in decision.findings}))
        gate = "below threshold, accepted" if decision.approved else "at/above threshold, rejected"
        reason = f"CCRS={ccrs} indicators={indicators} ({gate})"
    return Stage(
        control="L1.onboarding",
        layer="L1",
        decision="approve" if decision.approved else "deny",
        blocked=not decision.approved,
        reason=reason,
        evidence={
            "rule_ids": [f.rule_id for f in decision.findings],
            "vulnerability_ids": sorted({f.vulnerability_id for f in decision.findings}),
            "ccrs": None if decision.risk is None else decision.risk.raw_score,
            "parse_error": decision.parse_error,
        },
    )


def _payment_stage(decision) -> Stage:
    if decision.approved:
        control, layer = "full-path.approval", "L1+L2+L3"
    elif decision.blocked_at == "L1":
        control, layer = "L1.gate", "L1"
    else:
        control, layer = f"{decision.blocked_at}.enforcement", decision.blocked_at
    return Stage(
        control=control,
        layer=layer,
        decision="approve" if decision.approved else "deny",
        blocked=not decision.approved,
        reason=decision.reason,
        evidence={},
    )


def _minimization_stage() -> Stage:
    payload = {
        "order_id": "order-demo",
        "pan": "4111111111111111",
        "cvv": "123",
        "ssn": "123-45-6789",
        "user": {"password": "hunter2", "name": "Victim"},
    }
    sanitized = minimize_response(payload)
    return Stage(
        control="L2.minimization",
        layer="L2",
        decision="sanitize",
        blocked=False,
        reason="sensitive fields removed and identifiers masked",
        evidence={
            "pan": sanitized.get("pan"),
            "cvv_present": "cvv" in sanitized,
            "password_present": "password" in sanitized.get("user", {}),
            "ssn": sanitized.get("ssn"),
        },
    )


def _finalize(
    chain: str,
    kind: str,
    seed: int,
    index: int,
    variation: Dict[str, object],
    stages: List[Stage],
) -> Trial:
    blocking = next((stage for stage in stages if stage.blocked), None)
    first_layer = blocking.layer if blocking else ""
    expected_layer = CHAIN_EXPECTED_LAYER[chain] if kind == "attack" else ""
    expected_outcome = "block" if kind == "attack" else "allow"
    outcome = "block" if blocking else "allow"
    if kind == "attack":
        matched = outcome == "block" and first_layer == expected_layer
    else:
        matched = outcome == "allow"
    return Trial(
        trial_id=f"{chain}-{kind[0].upper()}{index:05d}",
        chain=chain,
        kind=kind,
        seed=seed,
        index=index,
        indicators=CHAIN_INDICATORS[chain],
        expected_layer=expected_layer,
        expected_outcome=expected_outcome,
        outcome=outcome,
        first_blocking_layer=first_layer,
        matched_expectation=matched,
        input_variation=variation,
        stages=tuple(stages),
    )


def build_attack_trial(chain: str, index: int, seed: int) -> Trial:
    if chain not in CHAIN_INDICATORS:
        raise ValueError(f"unknown chain {chain!r}")
    rng = _rng(seed, chain, index, "attack")
    gateway = _new_gateway()
    _, claims, signature, now = _base_context(gateway, index)
    victim = Principal("user-victim", Role.USER)
    request = TransactionRequest(
        MERCHANT_ID, "user-victim", f"order-{index}", BASE_AMOUNT_MINOR, "USD", claims, signature
    )
    stages: List[Stage] = []
    variation: Dict[str, object] = {}

    if chain in ("C1", "C4"):
        token = f"{rng.randrange(10**9):09d}"
        source = (
            malicious_source_c1(index, token)
            if chain == "C1"
            else malicious_source_c4(index, token)
        )
        variation = {"submission": source, "secret": token}
        stages.append(_onboarding_stage(gateway.onboard_merchant(MERCHANT_ID, source)))
        stages.append(_payment_stage(gateway.process(victim, request, now=now)))
    elif chain == "C2":
        attacker = f"attacker-{rng.randrange(1_000_000)}"
        owner = f"user-{rng.randrange(1_000_000)}"
        variation = {"attacker_id": attacker, "target_owner_id": owner}
        stages.append(_onboarding_stage(gateway.onboard_merchant(MERCHANT_ID, clean_source(index))))
        idor_request = TransactionRequest(
            MERCHANT_ID, owner, f"order-{index}", BASE_AMOUNT_MINOR, "USD", claims, signature
        )
        stages.append(_payment_stage(gateway.process(Principal(attacker, Role.USER), idor_request, now=now)))
        stages.append(_minimization_stage())
    elif chain == "C3":
        tampered = rng.randrange(1, BASE_AMOUNT_MINOR)
        variation = {"signed_amount_minor": BASE_AMOUNT_MINOR, "presented_amount_minor": tampered}
        stages.append(_onboarding_stage(gateway.onboard_merchant(MERCHANT_ID, weak_crypto_source_c3(index))))
        tampered_request = TransactionRequest(
            MERCHANT_ID, "user-victim", f"order-{index}", tampered, "USD", claims, signature
        )
        stages.append(_payment_stage(gateway.process(victim, tampered_request, now=now)))
    return _finalize(chain, "attack", seed, index, variation, stages)


def build_control_trial(chain: str, index: int, seed: int) -> Trial:
    if chain not in CHAIN_INDICATORS:
        raise ValueError(f"unknown chain {chain!r}")
    rng = _rng(seed, chain, index, "control")
    gateway = _new_gateway()
    _, claims, signature, now = _base_context(gateway, index)
    owner = Principal("user-victim", Role.USER)
    request = TransactionRequest(
        MERCHANT_ID, "user-victim", f"order-{index}", BASE_AMOUNT_MINOR, "USD", claims, signature
    )
    variation = {"order_id": f"order-{index}", "amount_minor": BASE_AMOUNT_MINOR, "nonce_seed": rng.randrange(10**6)}
    stages: List[Stage] = []
    stages.append(_onboarding_stage(gateway.onboard_merchant(MERCHANT_ID, clean_source(index))))
    stages.append(_payment_stage(gateway.process(owner, request, now=now)))
    return _finalize(chain, "control", seed, index, variation, stages)
