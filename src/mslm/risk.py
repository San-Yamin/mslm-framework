"""CCRS calculation with explicit validation and research assumptions."""

from dataclasses import dataclass
from enum import Enum
from math import prod
from typing import Iterable, Tuple


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class CCRSResult:
    scores: Tuple[float, ...]
    raw_score: float
    deployment_score: float
    max_cvss: float
    amplification_percent: float
    severity: Severity
    assumption: str = "independent cumulative-complement aggregation"


def classify(score: float) -> Severity:
    if not 0.0 <= score <= 10.0:
        raise ValueError("score must be in [0, 10]")
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def calculate_ccrs(
    cvss_scores: Iterable[float],
    *,
    deployment_cap: float = 9.8,
) -> CCRSResult:
    """Calculate the paper's cumulative-complement CCRS.

    This function deliberately does not call CVSS scores probabilities. That
    interpretation requires independent empirical calibration.
    """
    scores = tuple(float(value) for value in cvss_scores)
    if not scores:
        raise ValueError("at least one CVSS score is required")
    if any(not 0.0 <= value <= 10.0 for value in scores):
        raise ValueError("every CVSS score must be in [0, 10]")
    if not 0.0 < deployment_cap <= 10.0:
        raise ValueError("deployment_cap must be in (0, 10]")

    raw = 10.0 * (1.0 - prod(1.0 - value / 10.0 for value in scores))
    maximum = max(scores)
    amplification = 0.0 if maximum == 0 else ((raw - maximum) / maximum) * 100.0
    deployment = min(raw, deployment_cap)
    return CCRSResult(
        scores=scores,
        raw_score=round(raw, 6),
        deployment_score=round(deployment, 6),
        max_cvss=maximum,
        amplification_percent=round(amplification, 6),
        severity=classify(deployment),
    )


PAPER_CHAINS = {
    "C1": (7.5, 7.2),
    "C2": (6.5, 6.2),
    "C3": (8.1, 5.9),
    "C4": (7.5, 7.2, 6.5, 8.1),
}


def maximum_cvss(scores: Iterable[float]) -> float:
    """Highest single severity in the set (baseline aggregator)."""
    values = tuple(float(value) for value in scores)
    if not values:
        raise ValueError("at least one CVSS score is required")
    return max(values)


def mean_cvss(scores: Iterable[float]) -> float:
    """Arithmetic mean severity (baseline aggregator)."""
    values = tuple(float(value) for value in scores)
    if not values:
        raise ValueError("at least one CVSS score is required")
    return sum(values) / len(values)


def capped_sum(scores: Iterable[float], *, cap: float = 10.0) -> float:
    """Sum of severities, saturated at ``cap`` (baseline aggregator)."""
    values = tuple(float(value) for value in scores)
    if not values:
        raise ValueError("at least one CVSS score is required")
    if not 0.0 < cap <= 10.0:
        raise ValueError("cap must be in (0, 10]")
    return min(sum(values), cap)


def sequential_product(scores: Iterable[float], *, scale: float = 10.0) -> float:
    """All-steps-succeed joint product rescaled to 0-10.

    This answers "do all encoded steps succeed?" rather than "how much
    cumulative severity is present?". It decreases as steps are added and is
    shown only as a contrast to CCRS, not as a recommendation.
    """
    values = tuple(float(value) for value in scores)
    if not values:
        raise ValueError("at least one CVSS score is required")
    if any(not 0.0 <= value <= 10.0 for value in values):
        raise ValueError("every CVSS score must be in [0, 10]")
    return scale * prod(value / 10.0 for value in values)


@dataclass(frozen=True)
class AggregationComparison:
    scores: Tuple[float, ...]
    maximum: float
    mean: float
    capped_sum: float
    sequential_product: float
    ccrs: float

    def as_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)


def compare_aggregations(scores: Iterable[float]) -> AggregationComparison:
    """Compute CCRS beside standard single-value and summing baselines.

    The comparison describes mathematical behaviour. It is not evidence that
    CCRS prioritises real-world remediation better than these baselines.
    """
    values = tuple(float(value) for value in scores)
    return AggregationComparison(
        scores=values,
        maximum=round(maximum_cvss(values), 6),
        mean=round(mean_cvss(values), 6),
        capped_sum=round(capped_sum(values), 6),
        sequential_product=round(sequential_product(values), 6),
        ccrs=calculate_ccrs(values).raw_score,
    )


@dataclass(frozen=True)
class ChainStep:
    """A single claimed step of a candidate attack chain.

    ``prerequisite``, ``trust_boundary`` and ``evidence`` are declarative
    statements the analyst must supply before the step is eligible for chain
    scoring. They are not inferred automatically.
    """

    vulnerability_id: str
    cvss: float
    prerequisite: str
    trust_boundary: str
    evidence: str


@dataclass(frozen=True)
class PlausibilityAssessment:
    chain_id: str
    plausible: bool
    step_count: int
    prerequisites: Tuple[str, ...]
    trust_boundaries: Tuple[str, ...]
    evidence: Tuple[str, ...]
    cvss_scores: Tuple[float, ...]
    gaps: Tuple[str, ...]
    notes: str


def assess_chain_plausibility(
    chain_id: str,
    steps: Iterable[ChainStep],
) -> PlausibilityAssessment:
    """Decide whether declared steps may be treated as a plausible chain.

    A chain is accepted only when it has at least two steps and every step
    declares a prerequisite, a crossed trust boundary, and supporting evidence.
    This is a transparency gate, not a reachability engine: it records what the
    analyst asserts so reviewers can see the basis for grouping vulnerabilities.
    CCRS ordering is unaffected, because the metric is permutation invariant.
    """
    materialized = tuple(steps)
    gaps = []
    if len(materialized) < 2:
        gaps.append("a chain requires at least two steps")
    for position, step in enumerate(materialized, start=1):
        if not step.prerequisite.strip():
            gaps.append(f"step {position} ({step.vulnerability_id}) missing prerequisite")
        if not step.trust_boundary.strip():
            gaps.append(f"step {position} ({step.vulnerability_id}) missing trust boundary")
        if not step.evidence.strip():
            gaps.append(f"step {position} ({step.vulnerability_id}) missing evidence")
    return PlausibilityAssessment(
        chain_id=chain_id,
        plausible=not gaps,
        step_count=len(materialized),
        prerequisites=tuple(step.prerequisite for step in materialized),
        trust_boundaries=tuple(step.trust_boundary for step in materialized),
        evidence=tuple(step.evidence for step in materialized),
        cvss_scores=tuple(step.cvss for step in materialized),
        gaps=tuple(gaps),
        notes=(
            "Plausibility is analyst-declared metadata; CCRS itself is "
            "permutation invariant and does not encode order, reachability, or "
            "conditional dependence. An unreachable or irrelevant weakness still "
            "raises CCRS if it is included in the input set."
        ),
    )


def score_plausible_chain(assessment: PlausibilityAssessment) -> CCRSResult:
    """Score a chain only after its plausibility gate has passed."""
    if not assessment.plausible:
        raise ValueError(
            "chain failed plausibility assessment: " + "; ".join(assessment.gaps)
        )
    return calculate_ccrs(assessment.cvss_scores)

