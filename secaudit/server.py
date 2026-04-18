from __future__ import annotations
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .scanners import scan_secrets, scan_code, scan_cloud_config
from .frameworks import map_controls, SUPPORTED_FRAMEWORKS
from .reporter import technical, compliance, executive
from .models import Finding

app = Server("sec-audit-mcp")
_findings: list[Finding] = []
_target: str = ""


def _fmt(obj) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(obj, indent=2, default=str))]


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="audit_secrets",
            description="Scan a directory for exposed credentials, API keys, and secret material (CASP+ / CISM)",
            inputSchema={"type": "object", "properties": {
                "path": {"type": "string", "description": "Directory to scan"},
            }, "required": ["path"]},
        ),
        Tool(
            name="audit_code",
            description="Scan source code for security vulnerabilities: injection, weak crypto, insecure functions (CASP+)",
            inputSchema={"type": "object", "properties": {
                "path":      {"type": "string"},
                "languages": {"type": "array", "items": {"type": "string"},
                              "description": "python, javascript, typescript, go, rust (default: all)"},
            }, "required": ["path"]},
        ),
        Tool(
            name="audit_cloud",
            description="Scan Terraform and CloudFormation for cloud misconfigurations: IAM, S3, network (CCSP)",
            inputSchema={"type": "object", "properties": {
                "path": {"type": "string"},
            }, "required": ["path"]},
        ),
        Tool(
            name="audit_all",
            description="Run all three scanners in one call — secrets + code + cloud",
            inputSchema={"type": "object", "properties": {
                "path": {"type": "string"},
            }, "required": ["path"]},
        ),
        Tool(
            name="map_controls",
            description="Map current findings to a compliance framework control list (CISA audit layer)",
            inputSchema={"type": "object", "properties": {
                "framework": {
                    "type": "string",
                    "enum": SUPPORTED_FRAMEWORKS,
                    "description": "NIST CSF | CIS v8 | SOC 2 | ISO 27001",
                },
            }, "required": ["framework"]},
        ),
        Tool(
            name="report_technical",
            description="Generate CASP+-level technical report: CWE IDs, evidence, per-finding remediation",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="report_compliance",
            description="Generate CISA-style audit report: findings organized by control framework",
            inputSchema={"type": "object", "properties": {
                "framework": {"type": "string", "enum": SUPPORTED_FRAMEWORKS},
            }},
        ),
        Tool(
            name="report_executive",
            description="Generate CISM-style executive risk summary: risk score, business impact, top 3 actions",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="clear_findings",
            description="Clear accumulated findings and start a new audit",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    global _findings, _target

    if name == "audit_secrets":
        path = arguments["path"]
        _target = path
        new = scan_secrets(path)
        _findings.extend(new)
        return _fmt({"scanner": "secrets", "path": path, "new_findings": len(new),
                     "total_findings": len(_findings),
                     "findings": [f.model_dump() for f in new]})

    if name == "audit_code":
        path = arguments["path"]
        _target = path
        new = scan_code(path, arguments.get("languages"))
        _findings.extend(new)
        return _fmt({"scanner": "code", "path": path, "new_findings": len(new),
                     "total_findings": len(_findings),
                     "findings": [f.model_dump() for f in new]})

    if name == "audit_cloud":
        path = arguments["path"]
        _target = path
        new = scan_cloud_config(path)
        _findings.extend(new)
        return _fmt({"scanner": "cloud", "path": path, "new_findings": len(new),
                     "total_findings": len(_findings),
                     "findings": [f.model_dump() for f in new]})

    if name == "audit_all":
        path = arguments["path"]
        _target = path
        s = scan_secrets(path)
        c = scan_code(path)
        cl = scan_cloud_config(path)
        all_new = s + c + cl
        _findings.extend(all_new)
        return _fmt({
            "scanner": "all",
            "path": path,
            "secrets": len(s),
            "code": len(c),
            "cloud": len(cl),
            "total_new": len(all_new),
            "total_accumulated": len(_findings),
        })

    if name == "map_controls":
        if not _findings:
            return _fmt({"error": "No findings. Run an audit scan first."})
        return _fmt(map_controls(_findings, arguments["framework"]))

    if name == "report_technical":
        if not _findings:
            return _fmt({"error": "No findings. Run an audit scan first."})
        return _fmt(technical(_findings, _target))

    if name == "report_compliance":
        if not _findings:
            return _fmt({"error": "No findings. Run an audit scan first."})
        fw = arguments.get("framework", "NIST CSF")
        return _fmt(compliance(_findings, _target, fw))

    if name == "report_executive":
        if not _findings:
            return _fmt({"error": "No findings. Run an audit scan first."})
        return _fmt(executive(_findings, _target))

    if name == "clear_findings":
        _findings = []
        _target = ""
        return _fmt({"status": "cleared"})

    return _fmt({"error": f"Unknown tool: {name}"})


def main() -> None:
    import asyncio
    asyncio.run(_run())


async def _run() -> None:
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())
