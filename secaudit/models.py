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


class Finding(BaseModel):
    id: str                          # deterministic hash of title+affected
    title: str
    severity: Severity
    description: str
    evidence: str                    # snippet of code/config that triggered it
    affected: str                    # file:line or resource ARN/name
    cwe: Optional[int] = None        # CWE ID (CASP+ depth)
    tags: list[str] = Field(default_factory=list)
    remediation: str = ""

    @classmethod
    def make(
        cls,
        title: str,
        severity: Severity,
        description: str,
        evidence: str,
        affected: str,
        cwe: Optional[int] = None,
        tags: list[str] | None = None,
        remediation: str = "",
    ) -> "Finding":
        fid = hashlib.sha1(f"{title}:{affected}".encode()).hexdigest()[:12]
        return cls(
            id=fid,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            affected=affected,
            cwe=cwe,
            tags=tags or [],
            remediation=remediation,
        )


# Risk weight per severity (CISM risk quantification)
RISK_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH:     15,
    Severity.MEDIUM:    7,
    Severity.LOW:       2,
    Severity.INFO:      0,
}


def risk_score(findings: list[Finding]) -> int:
    """0–100 composite risk score. >75 = critical posture."""
    raw = sum(RISK_WEIGHT[f.severity] for f in findings)
    return min(100, raw)


def risk_label(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "MINIMAL"
