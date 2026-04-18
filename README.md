# sec-audit-mcp

Security audit as a [Model Context Protocol](https://modelcontextprotocol.io) server.

Four certification domains, one tool. Point it at a codebase or cloud config — get findings at the right level for every audience.

| Layer | Cert | What it produces |
|---|---|---|
| Technical scanning | CASP+ | CWE IDs, evidence snippets, per-finding remediation |
| Cloud controls | CCSP | IAM, S3, network misconfiguration findings |
| Compliance mapping | CISA | Findings organized by NIST CSF / CIS v8 / SOC 2 / ISO 27001 controls |
| Executive reporting | CISM | Risk score 0–100, business impact, top 3 priority actions |

---

## Install

```bash
pip install sec-audit-mcp
```

## Claude Code integration

Add to `.claude/mcp_servers.json`:

```json
{
  "sec-audit": {
    "command": "sec-audit-mcp",
    "args": []
  }
}
```

Then ask Claude Code:

```
audit the repo at ./my-service for security issues, map findings to SOC 2 controls,
and give me an executive summary with risk score
```

---

## Tools

| Tool | Layer | Description |
|---|---|---|
| `audit_secrets` | CASP+ | Credentials, API keys, private keys in source |
| `audit_code` | CASP+ | Injection, weak crypto, insecure functions |
| `audit_cloud` | CCSP | Terraform / CloudFormation misconfigurations |
| `audit_all` | All | Run all three scanners at once |
| `map_controls` | CISA | Map findings → NIST CSF / CIS v8 / SOC 2 / ISO 27001 |
| `report_technical` | CASP+ | Full technical report with CWE IDs and evidence |
| `report_compliance` | CISA | Audit report organized by control |
| `report_executive` | CISM | Risk score, headline, top 3 actions for leadership |
| `clear_findings` | — | Reset for a new audit target |

---

## Example session

```
audit_all("./my-service")
→ secrets: 2, code: 5, cloud: 3  (10 total findings)

map_controls(framework="SOC 2")
→ CC6.1: [f1, f2, f3]
  CC6.6: [f4, f5]
  CC6.7: [f1, f6]
  ...

report_executive()
→ risk_score: 72
  risk_posture: HIGH
  headline: "3 critical vulnerabilities present an immediate breach risk."
  priority_actions:
    1. Rotate exposed API key. Store in vault.
    2. Replace wildcard IAM policy with least-privilege.
    3. Enable S3 encryption at rest.

report_compliance(framework="NIST CSF")
→ audit_opinion: "QUALIFIED — Critical control deficiencies identified"
  controls_deficient: ["PR.AC-1", "PR.DS-2", "PR.AC-4"]
  ...

report_technical()
→ Full findings with CWE-798, CWE-269, CWE-311 ...
```

---

## Scanners

### Secrets (CASP+ / CISA)
Detects: AWS keys, Anthropic/OpenAI API keys, GitHub tokens, PEM private keys, hardcoded passwords, credentials in URLs, generic high-entropy secrets.

### Code (CASP+)
Detects: `eval()`/`exec()`, `subprocess` with `shell=True`, f-string SQL injection, pickle deserialization, weak hash algorithms (MD5/SHA-1), insecure `random` for security, `assert` used as auth gate, security-relevant TODO comments.

### Cloud Config (CCSP)
Detects: Public S3 ACLs, S3 without encryption at rest, wildcard IAM actions (`*`), security groups open to `0.0.0.0/0`, S3 versioning without MFA delete. Supports Terraform (`.tf`) and CloudFormation (`.yaml`/`.json`).

---

## Compliance frameworks

| Framework | Version | Controls covered |
|---|---|---|
| NIST CSF | 2.0 | PR.AC, PR.DS, PR.PT, DE.CM, RS.MI |
| CIS Controls | v8 | IG1–IG3 safeguards |
| SOC 2 | TSC 2017 | CC6, CC7, A1 |
| ISO 27001 | 2022 | Annex A.5, A.8, A.9 |

---

## Architecture

```
secaudit/
├── models.py      # Finding, Severity, risk_score — shared data model
├── scanners.py    # CASP+/CCSP: secrets, code, cloud scanners (no network)
├── frameworks.py  # CISA: tag → control ID mapping for 4 frameworks
├── reporter.py    # CISM: technical / compliance / executive report generation
└── server.py      # MCP server — tool definitions and dispatch
```

Findings accumulate across tool calls in a session. Run multiple scanners, then generate all three report types from the same finding set.

---

## Credits

Built with Claude (Anthropic) and Codex (OpenAI).

## License

MIT
