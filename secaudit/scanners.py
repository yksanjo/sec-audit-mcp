"""
CASP+ layer — technical scanning.
Three scanners: secrets, code patterns, cloud config.
All return list[Finding]. No network calls.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from .models import Finding, Severity

# ── Secrets scanner ────────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, str, int, str]] = [
    # (pattern, title, CWE, remediation)
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", 798,
     "Rotate key immediately. Use IAM roles or AWS Secrets Manager."),
    (r"sk-ant-[a-zA-Z0-9\-_]{32,}", "Anthropic API Key", 798,
     "Rotate key. Store in vault, inject via environment variable."),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API Key", 798,
     "Rotate key. Store in vault, inject via environment variable."),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", 798,
     "Revoke token. Use GitHub Actions secrets or a secrets manager."),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key Material", 321,
     "Remove from repository. Use a hardware security module or secrets manager."),
    (r"(?i)password\s*=\s*['\"][^'\"]{4,}", "Hardcoded Password", 259,
     "Move to environment variable or secrets manager."),
    (r"(?i)(secret|token|api_key|apikey)\s*=\s*['\"][^'\"]{8,}", "Hardcoded Secret", 798,
     "Move to environment variable or secrets manager."),
    (r"[a-zA-Z]{3,10}://[^:@/\s]+:[^@/\s]+@", "Credentials in URL", 522,
     "Remove credentials from URLs. Use IAM auth or connection string secrets."),
]


def scan_secrets(path: str) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(path)
    extensions = {".py", ".js", ".ts", ".go", ".rs", ".yaml", ".yml",
                  ".json", ".env", ".sh", ".tf", ".toml", ".cfg", ".ini"}

    for file in root.rglob("*"):
        if not file.is_file():
            continue
        if file.suffix not in extensions:
            continue
        if any(p in file.parts for p in (".git", "node_modules", "__pycache__", "dist")):
            continue

        try:
            text = file.read_text(errors="ignore")
        except OSError:
            continue

        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern, title, cwe, remediation in _SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding.make(
                        title=title,
                        severity=Severity.CRITICAL,
                        description=f"Credential material detected in source code. {title} found in file.",
                        evidence=line.strip()[:120],
                        affected=f"{file}:{line_no}",
                        cwe=cwe,
                        tags=["secrets", "credential-exposure"],
                        remediation=remediation,
                    ))

    return findings


# ── Code pattern scanner ────────────────────────────────────────────────────

_CODE_PATTERNS: list[tuple[str, str, Severity, int, str, str, list[str]]] = [
    # (regex, title, severity, CWE, description, remediation, tags)
    (r"\beval\s*\(", "Use of eval()", Severity.HIGH, 95,
     "eval() executes arbitrary code. Attackers who control the input achieve RCE.",
     "Replace with a safe parser or explicit logic.", ["injection", "rce"]),

    (r"\bexec\s*\(", "Use of exec()", Severity.HIGH, 95,
     "exec() executes arbitrary code strings.",
     "Use subprocess with explicit args list, never shell strings.", ["injection", "rce"]),

    (r"subprocess\.[a-z_]+\(.*shell\s*=\s*True", "subprocess with shell=True", Severity.HIGH, 78,
     "shell=True with user-controlled input enables command injection.",
     "Pass args as a list. Never concatenate user input into shell commands.", ["injection", "command-injection"]),

    (r"f['\"].*SELECT.*\{", "Potential SQL Injection via f-string", Severity.HIGH, 89,
     "String-formatting SQL with user data enables SQL injection.",
     "Use parameterized queries or an ORM.", ["injection", "sqli"]),

    (r"pickle\.loads?\s*\(", "Insecure pickle Deserialization", Severity.HIGH, 502,
     "Unpickling untrusted data leads to arbitrary code execution.",
     "Use JSON or a safe serialization format for untrusted data.", ["deserialization"]),

    (r"\bhashlib\.(md5|sha1)\s*\(", "Weak Hash Algorithm", Severity.MEDIUM, 327,
     "MD5 and SHA-1 are cryptographically broken for integrity/signature use.",
     "Use SHA-256 or SHA-3. For passwords use bcrypt/argon2.", ["crypto", "weak-hash"]),

    (r"\brandom\.(random|randint|choice)\s*\(", "Insecure Random for Security", Severity.MEDIUM, 338,
     "random module is not cryptographically secure.",
     "Use secrets module for tokens, keys, and nonces.", ["crypto", "randomness"]),

    (r"\bassert\b.*(?:auth|role|permission|admin)", "Assert Used for Security Check", Severity.MEDIUM, 617,
     "assert statements are stripped in optimized Python (-O flag).",
     "Replace with explicit if/raise checks.", ["auth"]),

    (r"(?i)(TODO|FIXME|HACK|XXX).*(?:security|auth|crypto|vuln|secret)", "Security-Relevant TODO", Severity.LOW, None,
     "Security-related TODO comment suggests known unresolved weakness.",
     "Track in issue tracker; do not ship with known security gaps.", ["hygiene"]),
]


def scan_code(path: str, languages: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(path)
    lang_map = {
        "python": {".py"},
        "javascript": {".js", ".mjs", ".cjs"},
        "typescript": {".ts", ".tsx"},
        "go": {".go"},
        "rust": {".rs"},
    }
    if languages:
        allowed = set()
        for lang in languages:
            allowed |= lang_map.get(lang.lower(), set())
    else:
        allowed = {ext for exts in lang_map.values() for ext in exts}

    for file in root.rglob("*"):
        if not file.is_file() or file.suffix not in allowed:
            continue
        if any(p in file.parts for p in (".git", "node_modules", "__pycache__", "dist", "vendor")):
            continue

        try:
            text = file.read_text(errors="ignore")
        except OSError:
            continue

        for line_no, line in enumerate(text.splitlines(), 1):
            for pat, title, severity, cwe, desc, remediation, tags in _CODE_PATTERNS:
                if re.search(pat, line):
                    findings.append(Finding.make(
                        title=title,
                        severity=severity,
                        description=desc,
                        evidence=line.strip()[:120],
                        affected=f"{file}:{line_no}",
                        cwe=cwe,
                        tags=tags,
                        remediation=remediation,
                    ))

    return findings


# ── Cloud config scanner (CCSP) ────────────────────────────────────────────

def scan_cloud_config(path: str) -> list[Finding]:
    """
    Parse Terraform (.tf), CloudFormation (.yaml/.json), and generic cloud
    config files for common misconfigurations. CCSP control focus.
    """
    findings: list[Finding] = []
    root = Path(path)

    for file in root.rglob("*"):
        if not file.is_file():
            continue
        if any(p in file.parts for p in (".git", "node_modules", "__pycache__")):
            continue

        suffix = file.suffix.lower()
        try:
            text = file.read_text(errors="ignore")
        except OSError:
            continue

        # Terraform checks
        if suffix == ".tf":
            findings += _check_terraform(text, str(file))

        # CloudFormation / generic YAML/JSON
        if suffix in (".yaml", ".yml", ".json"):
            findings += _check_cloudformation(text, str(file))

    return findings


def _check_terraform(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []

    # Public S3 bucket
    if re.search(r'acl\s*=\s*"public-read', text):
        findings.append(Finding.make(
            title="S3 Bucket Publicly Readable",
            severity=Severity.CRITICAL,
            description="S3 ACL set to public-read exposes all objects to the internet. Violates CCSP shared responsibility model.",
            evidence='acl = "public-read"',
            affected=path,
            cwe=732,
            tags=["cloud", "s3", "data-exposure"],
            remediation="Set acl to private. Use bucket policies for controlled access. Enable S3 Block Public Access.",
        ))

    # No encryption at rest
    if "aws_s3_bucket" in text and "server_side_encryption" not in text:
        findings.append(Finding.make(
            title="S3 Bucket Without Encryption at Rest",
            severity=Severity.HIGH,
            description="S3 bucket has no server-side encryption configured. Violates CCSP data-at-rest controls.",
            evidence="aws_s3_bucket resource without server_side_encryption_configuration",
            affected=path,
            cwe=311,
            tags=["cloud", "s3", "encryption"],
            remediation="Add server_side_encryption_configuration with AES256 or aws:kms.",
        ))

    # Wildcard IAM
    if re.search(r'"Action"\s*:\s*"\*"', text) or re.search(r'actions\s*=\s*\["\*"\]', text):
        findings.append(Finding.make(
            title="IAM Policy Grants Wildcard Actions (*)",
            severity=Severity.CRITICAL,
            description="Wildcard action in IAM policy violates principle of least privilege. Full account compromise if credentials are exposed.",
            evidence='"Action": "*"',
            affected=path,
            cwe=269,
            tags=["cloud", "iam", "least-privilege"],
            remediation="Enumerate only required actions. Use IAM Access Analyzer to generate least-privilege policies.",
        ))

    # Security group open to world
    if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', text):
        findings.append(Finding.make(
            title="Security Group Open to 0.0.0.0/0",
            severity=Severity.HIGH,
            description="Inbound rule allows traffic from any IP. Exposes service to the entire internet.",
            evidence='cidr_blocks = ["0.0.0.0/0"]',
            affected=path,
            cwe=284,
            tags=["cloud", "network", "exposure"],
            remediation="Restrict to known IP ranges. Use VPC endpoints or private networking.",
        ))

    # No MFA delete on S3
    if "aws_s3_bucket" in text and "mfa_delete" not in text:
        findings.append(Finding.make(
            title="S3 Versioning Without MFA Delete",
            severity=Severity.MEDIUM,
            description="S3 bucket versioning is enabled but MFA delete is not enforced. Allows accidental or malicious deletion without MFA.",
            evidence="S3 bucket without mfa_delete = Enabled",
            affected=path,
            cwe=306,
            tags=["cloud", "s3", "data-integrity"],
            remediation="Enable MFA delete on versioned buckets containing sensitive data.",
        ))

    return findings


def _check_cloudformation(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []

    if re.search(r"PublicRead|public-read", text, re.IGNORECASE):
        findings.append(Finding.make(
            title="CloudFormation: Public S3 ACL",
            severity=Severity.CRITICAL,
            description="CloudFormation template sets S3 ACL to public-read.",
            evidence="PublicRead ACL in CloudFormation template",
            affected=path,
            cwe=732,
            tags=["cloud", "cloudformation", "s3"],
            remediation="Set AccessControl to Private. Enable PublicAccessBlockConfiguration.",
        ))

    if re.search(r'"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"', text, re.DOTALL):
        findings.append(Finding.make(
            title="CloudFormation: IAM Wildcard Allow",
            severity=Severity.CRITICAL,
            description="IAM policy in CloudFormation template grants all actions.",
            evidence='Effect: Allow, Action: "*"',
            affected=path,
            cwe=269,
            tags=["cloud", "cloudformation", "iam"],
            remediation="Enumerate required actions explicitly.",
        ))

    return findings
