from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import hashlib


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Confidence(str, Enum):
    """
    CISA audit layer: evidence quality rating.
    Only HIGH confidence findings appear in compliance reports by default.
    LOW confidence = informational, review manually before acting.
    """
    HIGH   = "high"    # entropy-verified, specific pattern, non-test file
    MEDIUM = "medium"  # pattern matched but context ambiguous
    LOW    = "low"     # heuristic match, likely needs human review


class RiskTreatment(str, Enum):
    """CISM risk treatment options per ISO 27005."""
    MITIGATE = "mitigate"   # apply control to reduce likelihood/impact
    ACCEPT   = "accept"     # residual risk within tolerance
    TRANSFER = "transfer"   # insurance, third-party SLA
    AVOID    = "avoid"      # discontinue the activity


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    description: str
    evidence: str
    affected: str
    cwe: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    remediation: str = ""
    risk_treatment: RiskTreatment = RiskTreatment.MITIGATE
    suppressed: bool = False
    suppression_reason: str = ""

    @classmethod
    def make(
        cls,
        title: str,
        severity: Severity,
        description: str,
        evidence: str,
        affected: str,
        confidence: Confidence = Confidence.HIGH,
        cwe: Optional[int] = None,
        tags: list[str] | None = None,
        remediation: str = "",
        risk_treatment: RiskTreatment = RiskTreatment.MITIGATE,
    ) -> "Finding":
        fid = hashlib.sha1(f"{title}:{affected}".encode()).hexdigest()[:12]
        return cls(
            id=fid,
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            affected=affected,
            cwe=cwe,
            tags=tags or [],
            remediation=remediation,
            risk_treatment=risk_treatment,
        )


# CISM risk weight — only active (non-suppressed) findings count
RISK_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH:     15,
    Severity.MEDIUM:    7,
    Severity.LOW:       2,
    Severity.INFO:      0,
}

# Confidence multiplier — low confidence findings carry less risk weight
CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.HIGH:   1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW:    0.2,
}


def active(findings: list[Finding]) -> list[Finding]:
    """Findings that are not suppressed."""
    return [f for f in findings if not f.suppressed]


def risk_score(findings: list[Finding]) -> int:
    """
    0–100 composite risk score weighted by severity and confidence.
    Only non-suppressed findings contribute.
    """
    raw = sum(
        RISK_WEIGHT[f.severity] * CONFIDENCE_MULTIPLIER[f.confidence]
        for f in findings
        if not f.suppressed
    )
    return min(100, int(raw))


def risk_label(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "MINIMAL"
