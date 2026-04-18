"""
CISA layer — compliance control mapping.
Maps finding tags to control IDs across NIST CSF, CIS Controls v8,
SOC 2 TSC, and ISO 27001:2022.
"""
from __future__ import annotations
from .models import Finding

# tag → {framework: [control_ids]}
_CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    "secrets": {
        "NIST CSF":   ["PR.AC-1", "PR.DS-2"],
        "CIS v8":     ["5.1", "5.4", "16.9"],
        "SOC 2":      ["CC6.1", "CC6.7"],
        "ISO 27001":  ["A.5.17", "A.8.24"],
    },
    "credential-exposure": {
        "NIST CSF":   ["PR.AC-1", "PR.DS-2", "DE.CM-7"],
        "CIS v8":     ["5.4", "16.9"],
        "SOC 2":      ["CC6.1", "CC6.7"],
        "ISO 27001":  ["A.5.17", "A.9.4.3"],
    },
    "injection": {
        "NIST CSF":   ["PR.DS-1", "DE.CM-8"],
        "CIS v8":     ["16.1", "16.2"],
        "SOC 2":      ["CC6.6", "CC7.1"],
        "ISO 27001":  ["A.8.28"],
    },
    "rce": {
        "NIST CSF":   ["PR.PT-3", "DE.CM-8", "RS.MI-1"],
        "CIS v8":     ["2.5", "16.1"],
        "SOC 2":      ["CC6.6", "CC7.2"],
        "ISO 27001":  ["A.8.20", "A.8.28"],
    },
    "sqli": {
        "NIST CSF":   ["PR.DS-1"],
        "CIS v8":     ["16.2"],
        "SOC 2":      ["CC6.6"],
        "ISO 27001":  ["A.8.28"],
    },
    "command-injection": {
        "NIST CSF":   ["PR.PT-3"],
        "CIS v8":     ["16.1"],
        "SOC 2":      ["CC6.6"],
        "ISO 27001":  ["A.8.28"],
    },
    "deserialization": {
        "NIST CSF":   ["PR.DS-1", "DE.CM-8"],
        "CIS v8":     ["16.1"],
        "SOC 2":      ["CC6.6"],
        "ISO 27001":  ["A.8.28"],
    },
    "crypto": {
        "NIST CSF":   ["PR.DS-2", "PR.DS-5"],
        "CIS v8":     ["3.11", "16.5"],
        "SOC 2":      ["CC6.1", "CC6.7"],
        "ISO 27001":  ["A.8.24"],
    },
    "weak-hash": {
        "NIST CSF":   ["PR.DS-2"],
        "CIS v8":     ["3.11"],
        "SOC 2":      ["CC6.1"],
        "ISO 27001":  ["A.8.24"],
    },
    "randomness": {
        "NIST CSF":   ["PR.DS-2"],
        "CIS v8":     ["16.5"],
        "SOC 2":      ["CC6.1"],
        "ISO 27001":  ["A.8.24"],
    },
    "auth": {
        "NIST CSF":   ["PR.AC-1", "PR.AC-7"],
        "CIS v8":     ["5.2", "6.3"],
        "SOC 2":      ["CC6.1", "CC6.3"],
        "ISO 27001":  ["A.9.4.1", "A.9.4.2"],
    },
    "cloud": {
        "NIST CSF":   ["PR.AC-3", "PR.DS-1"],
        "CIS v8":     ["1.1", "3.1", "5.1"],
        "SOC 2":      ["CC6.1", "CC6.6", "A1.1"],
        "ISO 27001":  ["A.5.23", "A.8.9"],
    },
    "s3": {
        "NIST CSF":   ["PR.DS-1", "PR.DS-5"],
        "CIS v8":     ["3.3"],
        "SOC 2":      ["CC6.1", "A1.1"],
        "ISO 27001":  ["A.8.10"],
    },
    "iam": {
        "NIST CSF":   ["PR.AC-1", "PR.AC-4"],
        "CIS v8":     ["5.4", "6.1"],
        "SOC 2":      ["CC6.3"],
        "ISO 27001":  ["A.5.15", "A.5.18"],
    },
    "least-privilege": {
        "NIST CSF":   ["PR.AC-4"],
        "CIS v8":     ["6.1", "6.8"],
        "SOC 2":      ["CC6.3"],
        "ISO 27001":  ["A.5.15"],
    },
    "encryption": {
        "NIST CSF":   ["PR.DS-1", "PR.DS-2"],
        "CIS v8":     ["3.11"],
        "SOC 2":      ["CC6.1"],
        "ISO 27001":  ["A.8.24"],
    },
    "network": {
        "NIST CSF":   ["PR.AC-3", "PR.PT-4"],
        "CIS v8":     ["12.1", "12.2"],
        "SOC 2":      ["CC6.6"],
        "ISO 27001":  ["A.8.20"],
    },
    "data-exposure": {
        "NIST CSF":   ["PR.DS-5", "DE.CM-1"],
        "CIS v8":     ["3.1", "3.3"],
        "SOC 2":      ["CC6.1", "CC6.7"],
        "ISO 27001":  ["A.8.10"],
    },
    "data-integrity": {
        "NIST CSF":   ["PR.DS-6", "PR.DS-8"],
        "CIS v8":     ["3.5"],
        "SOC 2":      ["A1.2"],
        "ISO 27001":  ["A.8.16"],
    },
}

SUPPORTED_FRAMEWORKS = ["NIST CSF", "CIS v8", "SOC 2", "ISO 27001"]


def map_controls(findings: list[Finding], framework: str = "NIST CSF") -> dict:
    """
    Map findings to control IDs for the given framework.
    Returns {control_id: [finding_ids]} so auditors can
    organize evidence by control (CISA audit style).
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unknown framework: {framework!r}. Choose from {SUPPORTED_FRAMEWORKS}")

    control_map: dict[str, list[str]] = {}
    unmapped: list[str] = []

    for f in findings:
        controls_found = set()
        for tag in f.tags:
            for ctrl in _CONTROL_MAP.get(tag, {}).get(framework, []):
                controls_found.add(ctrl)
        if controls_found:
            for ctrl in controls_found:
                control_map.setdefault(ctrl, []).append(f.id)
        else:
            unmapped.append(f.id)

    return {
        "framework": framework,
        "controls_triggered": dict(sorted(control_map.items())),
        "finding_count": len(findings),
        "controls_count": len(control_map),
        "unmapped_findings": unmapped,
    }
