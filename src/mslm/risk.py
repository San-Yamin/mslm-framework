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

