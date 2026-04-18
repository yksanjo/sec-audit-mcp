"""
Three report formats, one set of findings.

- technical()   CASP+ depth: CWE IDs, entropy, confidence, remediation
- compliance()  CISA audit style: organized by control, confidence-gated evidence
- executive()   CISM style: risk score, risk treatment options, top 3 actions
"""
from __future__ import annotations
from datetime import date
from .models import (
    Confidence, Finding, RiskTreatment, Severity,
    active, risk_score, risk_label,
)
from .frameworks import map_controls, SUPPORTED_FRAMEWORKS

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# CISA: only HIGH confidence findings go into formal audit evidence by default
_AUDIT_CONFIDENCE = {Confidence.HIGH, Confidence.MEDIUM}

_TREATMENT_SLA: dict[RiskTreatment, str] = {
    RiskTreatment.MITIGATE:  "Remediate within SLA: CRITICAL=24h, HIGH=7d, MEDIUM=30d, LOW=90d",
    RiskTreatment.ACCEPT:    "Document accepted risk with business owner sign-off. Review quarterly.",
    RiskTreatment.TRANSFER:  "Confirm coverage with insurance/vendor SLA. Document scope.",
    RiskTreatment.AVOID:     "Discontinue the activity or feature generating this risk.",
}


def technical(findings: list[Finding], target: str) -> dict:
    """
    CASP+ level — full technical depth.
    Includes suppressed findings (marked) and all confidence levels.
    """
    by_sev: dict[str, list[dict]] = {s.value: [] for s in _SEV_ORDER}
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x.severity)):
        by_sev[f.severity.value].append({
            "id":          f.id,
            "title":       f.title,
            "cwe":         f"CWE-{f.cwe}" if f.cwe else None,
            "confidence":  f.confidence.value,
            "affected":    f.affected,
            "evidence":    f.evidence,
            "description": f.description,
            "remediation": f.remediation,
            "tags":        f.tags,
            "suppressed":  f.suppressed,
            "suppression_reason": f.suppression_reason or None,
        })

    act = active(findings)
    return {
        "report_type": "Technical Security Assessment (CASP+)",
        "target":      target,
        "date":        str(date.today()),
        "summary": {
            "total":              len(findings),
            "active":             len(act),
            "suppressed":         len(findings) - len(act),
            "high_confidence":    sum(1 for f in act if f.confidence == Confidence.HIGH),
            "medium_confidence":  sum(1 for f in act if f.confidence == Confidence.MEDIUM),
            "low_confidence":     sum(1 for f in act if f.confidence == Confidence.LOW),
            "critical":           sum(1 for f in act if f.severity == Severity.CRITICAL),
            "high":               sum(1 for f in act if f.severity == Severity.HIGH),
            "medium":             sum(1 for f in act if f.severity == Severity.MEDIUM),
            "low":                sum(1 for f in act if f.severity == Severity.LOW),
        },
        "findings_by_severity": by_sev,
    }


def compliance(
    findings: list[Finding],
    target: str,
    framework: str = "NIST CSF",
    min_confidence: str = "medium",
) -> dict:
    """
    CISA audit style — evidence organized by control.
    Only non-suppressed findings at or above min_confidence appear as audit evidence.
    Low-confidence findings are surfaced separately as "observations requiring review."
    """
    min_conf = Confidence(min_confidence)
    conf_order = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
    min_idx = conf_order.index(min_conf)

    audit_findings = [
        f for f in active(findings)
        if conf_order.index(f.confidence) <= min_idx
    ]
    observations = [
        f for f in active(findings)
        if conf_order.index(f.confidence) > min_idx
    ]

    control_data = map_controls(audit_findings, framework)
    finding_index = {f.id: f for f in audit_findings}

    controls_detail: dict[str, list[dict]] = {}
    for ctrl, fids in control_data["controls_triggered"].items():
        controls_detail[ctrl] = [
            {
                "finding_id": fid,
                "title":      finding_index[fid].title,
                "severity":   finding_index[fid].severity.value,
                "confidence": finding_index[fid].confidence.value,
                "affected":   finding_index[fid].affected,
                "evidence":   finding_index[fid].evidence,
            }
            for fid in fids if fid in finding_index
        ]

    critical_controls = [
        ctrl for ctrl, fids in control_data["controls_triggered"].items()
        if any(
            finding_index[fid].severity in (Severity.CRITICAL, Severity.HIGH)
            for fid in fids if fid in finding_index
        )
    ]

    return {
        "report_type":        "Compliance Audit Report (CISA)",
        "framework":          framework,
        "target":             target,
        "date":               str(date.today()),
        "audit_opinion":      _audit_opinion(audit_findings),
        "evidence_quality":   f"Findings at {min_confidence}+ confidence included as audit evidence",
        "controls_assessed":  len(control_data["controls_triggered"]),
        "controls_deficient": len(critical_controls),
        "critical_controls":  critical_controls,
        "findings_by_control": controls_detail,
        "observations_requiring_review": [
            {"id": f.id, "title": f.title, "confidence": f.confidence.value, "affected": f.affected}
            for f in observations
        ],
        "suppressed_count":   len(findings) - len(active(findings)),
    }


def executive(findings: list[Finding], target: str) -> dict:
    """
    CISM style — for board / security leadership.
    Risk score weighted by confidence. Treatment options per CISM/ISO 27005.
    """
    act = active(findings)
    score = risk_score(act)
    label = risk_label(score)

    criticals = [f for f in act if f.severity == Severity.CRITICAL]
    highs     = [f for f in act if f.severity == Severity.HIGH]

    # Top 3 priority actions (deduped by title, highest severity first)
    priority: list[dict] = []
    seen: set[str] = set()
    for f in sorted(act, key=lambda x: _SEV_ORDER.index(x.severity)):
        if f.title not in seen and f.confidence in (Confidence.HIGH, Confidence.MEDIUM):
            priority.append({
                "action":     f.remediation or f.title,
                "severity":   f.severity.value,
                "confidence": f.confidence.value,
                "treatment":  f.risk_treatment.value,
                "sla":        _TREATMENT_SLA[f.risk_treatment],
            })
            seen.add(f.title)
        if len(priority) >= 3:
            break

    # Risk by category
    tag_counts: dict[str, int] = {}
    for f in act:
        for tag in f.tags:
            if tag != "test-file":
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

    # Treatment breakdown
    treatment_counts = {t.value: 0 for t in RiskTreatment}
    for f in act:
        treatment_counts[f.risk_treatment.value] += 1

    return {
        "report_type":    "Executive Risk Summary (CISM)",
        "target":         target,
        "date":           str(date.today()),
        "risk_score":     score,
        "risk_posture":   label,
        "headline":       _headline(score, criticals, highs),
        "finding_summary": {
            "total_active":                len(act),
            "suppressed":                  len(findings) - len(act),
            "requiring_immediate_action":  len(criticals),
            "requiring_prompt_action":     len(highs),
            "high_confidence_only":        sum(1 for f in act if f.confidence == Confidence.HIGH),
        },
        "top_risk_categories":    dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:5]),
        "risk_treatment_summary": treatment_counts,
        "priority_actions":       priority,
        "frameworks_applicable":  SUPPORTED_FRAMEWORKS,
        "recommendation":         _recommendation(score),
    }


def _audit_opinion(findings: list[Finding]) -> str:
    if any(f.severity == Severity.CRITICAL and f.confidence == Confidence.HIGH for f in findings):
        return "ADVERSE — Critical control deficiencies with high-confidence evidence. Immediate remediation required."
    if any(f.severity == Severity.CRITICAL for f in findings):
        return "QUALIFIED — Critical findings present (medium confidence). Verify and remediate."
    if any(f.severity == Severity.HIGH and f.confidence == Confidence.HIGH for f in findings):
        return "QUALIFIED — Significant deficiencies identified. Remediation required within 7 days."
    if findings:
        return "UNQUALIFIED WITH OBSERVATIONS — Minor deficiencies noted."
    return "UNQUALIFIED — No findings at current confidence threshold."


def _headline(score: int, criticals: list, highs: list) -> str:
    if score >= 75:
        return (
            f"{len(criticals)} critical-severity findings present immediate breach risk. "
            "Halt non-critical deployments pending remediation."
        )
    if score >= 50:
        return (
            f"{len(highs)} high-severity findings materially elevate organizational risk. "
            "Assign owners and target 7-day resolution."
        )
    if score >= 25:
        return "Moderate security posture. Known gaps should be addressed within current sprint cycle."
    return "Acceptable security posture. Maintain current review cadence."


def _recommendation(score: int) -> str:
    if score >= 75:
        return "IMMEDIATE: Activate incident response. Rotate all exposed credentials. Gate deployment pipeline."
    if score >= 50:
        return "URGENT: Assign remediation owners within 24h. Schedule penetration test. Brief CISO."
    if score >= 25:
        return "PLANNED: Include in next sprint. Update threat model. Review IAM quarterly."
    return "MONITOR: Maintain controls. Run automated scans on every PR."
