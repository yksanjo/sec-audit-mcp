from __future__ import annotations
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .scanners import scan_secrets, scan_code, scan_cloud_config, scan_containers
from .frameworks import map_controls, SUPPORTED_FRAMEWORKS
from .reporter import technical, compliance, executive
from .models import Confidence, Finding, RiskTreatment

app = Server("sec-audit-mcp")
_findings: list[Finding] = []
_seen_ids: set[str] = set()
_target: str = ""


def _fmt(obj) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(obj, indent=2, default=str))]


def _add(new: list[Finding]) -> list[Finding]:
    """Accumulate findings, deduplicating by id."""
    added = []
    for f in new:
        if f.id not in _seen_ids:
            _seen_ids.add(f.id)
            _findings.append(f)
            added.append(f)
    return added


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="audit_secrets",
             description="Scan for exposed credentials with entropy analysis — eliminates placeholder false positives (CASP+)",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),

        Tool(name="audit_code",
             description="Scan source code for injection, weak crypto, insecure patterns — skips test files (CASP+)",
             inputSchema={"type": "object", "properties": {
                 "path":      {"type": "string"},
                 "languages": {"type": "array", "items": {"type": "string"},
                               "description": "python, javascript, typescript, go, rust, ruby, java"},
             }, "required": ["path"]}),

        Tool(name="audit_cloud",
             description="Scan Terraform/CloudFormation for IAM, S3, network misconfigurations (CCSP)",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),

        Tool(name="audit_containers",
             description="Scan Dockerfiles and Kubernetes manifests for container security issues (CCSP cloud-native)",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),

        Tool(name="audit_all",
             description="Run all four scanners: secrets + code + cloud + containers",
             inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),

        Tool(name="map_controls",
             description="Map findings to compliance framework control IDs (CISA audit layer)",
             inputSchema={"type": "object", "properties": {
                 "framework": {"type": "string", "enum": SUPPORTED_FRAMEWORKS},
             }, "required": ["framework"]}),

        Tool(name="report_technical",
             description="CASP+ technical report: CWE IDs, entropy scores, confidence ratings, per-finding remediation",
             inputSchema={"type": "object", "properties": {}}),

        Tool(name="report_compliance",
             description="CISA audit report: findings by control, confidence-gated evidence, audit opinion",
             inputSchema={"type": "object", "properties": {
                 "framework":       {"type": "string", "enum": SUPPORTED_FRAMEWORKS},
                 "min_confidence":  {"type": "string", "enum": ["high", "medium", "low"],
                                     "description": "Minimum confidence for audit evidence (default: medium)"},
             }}),

        Tool(name="report_executive",
             description="CISM executive summary: confidence-weighted risk score, treatment options, board-ready actions",
             inputSchema={"type": "object", "properties": {}}),

        Tool(name="suppress_finding",
             description="Mark a finding as suppressed with a documented reason — CISA audit trail for accepted/false-positive findings",
             inputSchema={"type": "object", "properties": {
                 "finding_id": {"type": "string"},
                 "reason":     {"type": "string", "description": "Documented justification (required for audit trail)"},
                 "treatment":  {"type": "string", "enum": ["accept", "transfer", "avoid"],
                                "description": "Risk treatment decision (default: accept)"},
             }, "required": ["finding_id", "reason"]}),

        Tool(name="list_findings",
             description="List all accumulated findings with id, title, severity, confidence, suppression status",
             inputSchema={"type": "object", "properties": {
                 "severity":    {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                 "confidence":  {"type": "string", "enum": ["high", "medium", "low"]},
                 "suppressed":  {"type": "boolean"},
             }}),

        Tool(name="clear_findings",
             description="Clear all findings and start a new audit session",
             inputSchema={"type": "object", "properties": {}}),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    global _findings, _seen_ids, _target

    if name == "audit_secrets":
        path = arguments["path"]
        _target = path
        added = _add(scan_secrets(path))
        return _fmt({"scanner": "secrets", "path": path,
                     "new_findings": len(added), "total": len(_findings),
                     "findings": [_summary(f) for f in added]})

    if name == "audit_code":
        path = arguments["path"]
        _target = path
        added = _add(scan_code(path, arguments.get("languages")))
        return _fmt({"scanner": "code", "path": path,
                     "new_findings": len(added), "total": len(_findings),
                     "findings": [_summary(f) for f in added]})

    if name == "audit_cloud":
        path = arguments["path"]
        _target = path
        added = _add(scan_cloud_config(path))
        return _fmt({"scanner": "cloud", "path": path,
                     "new_findings": len(added), "total": len(_findings),
                     "findings": [_summary(f) for f in added]})

    if name == "audit_containers":
        path = arguments["path"]
        _target = path
        added = _add(scan_containers(path))
        return _fmt({"scanner": "containers", "path": path,
                     "new_findings": len(added), "total": len(_findings),
                     "findings": [_summary(f) for f in added]})

    if name == "audit_all":
        path = arguments["path"]
        _target = path
        s  = _add(scan_secrets(path))
        c  = _add(scan_code(path))
        cl = _add(scan_cloud_config(path))
        co = _add(scan_containers(path))
        return _fmt({
            "scanner": "all", "path": path,
            "secrets": len(s), "code": len(c),
            "cloud": len(cl), "containers": len(co),
            "total_new": len(s) + len(c) + len(cl) + len(co),
            "total_accumulated": len(_findings),
        })

    if name == "map_controls":
        if not _findings:
            return _fmt({"error": "No findings. Run a scan first."})
        from .models import active
        return _fmt(map_controls(active(_findings), arguments["framework"]))

    if name == "report_technical":
        if not _findings:
            return _fmt({"error": "No findings. Run a scan first."})
        return _fmt(technical(_findings, _target))

    if name == "report_compliance":
        if not _findings:
            return _fmt({"error": "No findings. Run a scan first."})
        fw   = arguments.get("framework", "NIST CSF")
        conf = arguments.get("min_confidence", "medium")
        return _fmt(compliance(_findings, _target, fw, conf))

    if name == "report_executive":
        if not _findings:
            return _fmt({"error": "No findings. Run a scan first."})
        return _fmt(executive(_findings, _target))

    if name == "suppress_finding":
        fid    = arguments["finding_id"]
        reason = arguments.get("reason", "")
        treat  = arguments.get("treatment", "accept")
        for f in _findings:
            if f.id == fid:
                f.suppressed = True
                f.suppression_reason = reason
                f.risk_treatment = RiskTreatment(treat)
                return _fmt({"suppressed": fid, "reason": reason, "treatment": treat})
        return _fmt({"error": f"Finding {fid!r} not found."})

    if name == "list_findings":
        results = _findings
        if "severity" in arguments:
            results = [f for f in results if f.severity.value == arguments["severity"]]
        if "confidence" in arguments:
            results = [f for f in results if f.confidence.value == arguments["confidence"]]
        if "suppressed" in arguments:
            results = [f for f in results if f.suppressed == arguments["suppressed"]]
        return _fmt([_summary(f) for f in results])

    if name == "clear_findings":
        _findings.clear()
        _seen_ids.clear()
        _target = ""
        return _fmt({"status": "cleared"})

    return _fmt({"error": f"Unknown tool: {name}"})


def _summary(f: Finding) -> dict:
    return {
        "id":         f.id,
        "title":      f.title,
        "severity":   f.severity.value,
        "confidence": f.confidence.value,
        "affected":   f.affected,
        "suppressed": f.suppressed,
        "treatment":  f.risk_treatment.value,
    }


def main() -> None:
    import asyncio
    asyncio.run(_run())


async def _run() -> None:
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())
