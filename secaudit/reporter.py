"""
Three report formats, one set of findings.

- technical()   CASP+ depth: CWE IDs, evidence, per-finding remediation
- compliance()  CISA audit style: organized by control, evidence mapped
- executive()   CISM style: risk score, trend, business impact, top 3 actions
"""
from __future__ import annotations
from datetime import date
from .models import Finding, Severity, risk_score, risk_label
from .frameworks import map_controls, SUPPORTED_FRAMEWORKS

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def technical(findings: list[Finding], target: str) -> dict:
    """CASP+ level technical security assessment."""
    by_sev: dict[str, list[dict]] = {s.value: [] for s in _SEV_ORDER}
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x.severity)):
        by_sev[f.severity.value].append({
            "id": f.id,
            "title": f.title,
            "cwe": f"CWE-{f.cwe}" if f.cwe else None,
            "affected": f.affected,
            "evidence": f.evidence,
            "description": f.description,
            "remediation": f.remediation,
            "tags": f.tags,
        })

    return {
        "report_type": "Technical Security Assessment",
        "target": target,
        "date": str(date.today()),
        "summary": {
            "total_findings": len(findings),
            "critical": len(by_sev["critical"]),
            "high":     len(by_sev["high"]),
            "medium":   len(by_sev["medium"]),
            "low":      len(by_sev["low"]),
            "info":     len(by_sev["info"]),
        },
        "findings_by_severity": by_sev,
    }


def compliance(findings: list[Finding], target: str, framework: str = "NIST CSF") -> dict:
    """CISA-style audit report: findings organized by control."""
    control_data = map_controls(findings, framework)
    finding_index = {f.id: f for f in findings}

    controls_detail = {}
    for ctrl, fids in control_data["controls_triggered"].items():
        controls_detail[ctrl] = [
            {
                "finding_id": fid,
                "title": finding_index[fid].title,
                "severity": finding_index[fid].severity.value,
                "affected": finding_index[fid].affected,
                "evidence": finding_index[fid].evidence,
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
        "report_type": "Compliance Audit Report",
        "framework": framework,
        "target": target,
        "date": str(date.today()),
        "audit_opinion": (
            "QUALIFIED — Critical control deficiencies identified"
            if any(f.severity == Severity.CRITICAL for f in findings)
            else "QUALIFIED — Significant deficiencies identified"
            if any(f.severity == Severity.HIGH for f in findings)
            else "UNQUALIFIED with observations"
        ),
        "controls_assessed": len(control_data["controls_triggered"]),
        "controls_deficient": len(critical_controls),
        "critical_controls": critical_controls,
        "findings_by_control": controls_detail,
        "unmapped_findings": control_data["unmapped_findings"],
    }


def executive(findings: list[Finding], target: str) -> dict:
    """CISM-style executive risk summary — for board / security leadership."""
    score = risk_score(findings)
    label = risk_label(score)

    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    highs     = [f for f in findings if f.severity == Severity.HIGH]

    # Top 3 priority actions
    priority = []
    seen_titles: set[str] = set()
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x.severity)):
        if f.title not in seen_titles:
            priority.append({"action": f.remediation or f.title, "severity": f.severity.value})
            seen_titles.add(f.title)
        if len(priority) >= 3:
            break

    # Business impact by category
    tag_counts: dict[str, int] = {}
    for f in findings:
        for tag in f.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    return {
        "report_type": "Executive Risk Summary",
        "target": target,
        "date": str(date.today()),
        "risk_score": score,
        "risk_posture": label,
        "headline": _headline(score, criticals, highs),
        "finding_summary": {
            "total": len(findings),
            "requiring_immediate_action": len(criticals),
            "requiring_prompt_action": len(highs),
        },
        "top_risk_categories": dict(
            sorted(tag_counts.items(), key=lambda x: -x[1])[:5]
        ),
        "priority_actions": priority,
        "frameworks_applicable": SUPPORTED_FRAMEWORKS,
        "recommendation": _recommendation(score),
    }


def _headline(score: int, criticals: list, highs: list) -> str:
    if score >= 75:
        return (
            f"{len(criticals)} critical vulnerabilities present an immediate breach risk. "
            "Halt deployments pending remediation."
        )
    if score >= 50:
        return (
            f"{len(highs)} high-severity findings significantly elevate organizational risk. "
            "Remediation required within 30 days."
        )
    if score >= 25:
        return "Moderate security posture. Known gaps should be addressed in the current sprint cycle."
    return "Security posture is acceptable. Continue scheduled review cadence."


def _recommendation(score: int) -> str:
    if score >= 75:
        return "IMMEDIATE: Engage incident response. Rotate all exposed credentials. Patch critical findings before next deployment."
    if score >= 50:
        return "URGENT: Assign remediation owners. Target 30-day resolution for high findings. Schedule penetration test."
    if score >= 25:
        return "PLANNED: Include in next sprint. Update security training. Review cloud IAM quarterly."
    return "MONITOR: Maintain current controls. Continue automated scanning cadence."
