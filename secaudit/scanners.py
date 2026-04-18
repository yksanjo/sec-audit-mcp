"""
CASP+ / CCSP technical scanning layer.

Scanners: secrets, code patterns, cloud config (Terraform/CloudFormation),
          containers (Dockerfile/K8s manifests).

All return list[Finding]. No network calls. No external dependencies.

False positive reduction strategy (per Philo Groves review):
  - Entropy analysis on extracted secret values
  - Placeholder detection ("changeme", "your_key", template syntax)
  - Test/fixture file exclusions
  - Confidence rating on every finding
"""
from __future__ import annotations
import re
from pathlib import Path
from .models import Confidence, Finding, RiskTreatment, Severity
from .entropy import is_high_entropy, is_placeholder, shannon

# ── Path exclusions ────────────────────────────────────────────────────────

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "dist", "build",
    ".pytest_cache", "vendor", "venv", ".venv", "coverage",
    ".nyc_output", "target",
}

_TEST_INDICATORS = {
    "test", "tests", "spec", "specs", "fixture", "fixtures",
    "mock", "mocks", "stub", "stubs", "fake", "example", "examples",
    "sample", "samples", "seed", "seeds", "demo",
}


def _is_test_file(path: Path) -> bool:
    parts_lower = {p.lower() for p in path.parts}
    name_lower = path.stem.lower()
    return (
        parts_lower & _TEST_INDICATORS
        or name_lower.startswith("test_")
        or name_lower.endswith("_test")
        or name_lower.endswith(".test")
        or name_lower.endswith(".spec")
        or name_lower.endswith("_mock")
        or "conftest" in name_lower
    )


def _skip(path: Path) -> bool:
    return bool({p for p in path.parts} & _SKIP_DIRS)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return None


# ── Secrets scanner ────────────────────────────────────────────────────────

# (regex, title, CWE, remediation, min_entropy)
# min_entropy=0.0 means the pattern itself is specific enough (e.g. AKIA prefix)
_SECRET_PATTERNS: list[tuple[str, str, int, str, float]] = [
    (r"AKIA[0-9A-Z]{16}",
     "AWS Access Key ID", 798,
     "Rotate immediately via IAM console. Audit CloudTrail for unauthorized use. Switch to IAM roles.",
     0.0),  # AKIA prefix + charset is specific enough

    (r"sk-ant-[a-zA-Z0-9\-_]{32,}",
     "Anthropic API Key", 798,
     "Rotate at console.anthropic.com/settings/keys. Audit usage logs.",
     0.0),

    (r"sk-[a-zA-Z0-9]{32,}",
     "OpenAI API Key", 798,
     "Rotate at platform.openai.com/account/api-keys. Check for unauthorized usage.",
     0.0),

    (r"ghp_[a-zA-Z0-9]{36}",
     "GitHub Personal Access Token", 798,
     "Revoke at github.com/settings/tokens. Use GitHub Actions OIDC instead.",
     0.0),

    (r"ghs_[a-zA-Z0-9]{36}",
     "GitHub Actions Secret Token", 798,
     "Token should never appear in source. Revoke immediately.",
     0.0),

    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private Key Material", 321,
     "Remove from repo. Rotate the key pair. Use HSM or secrets manager for storage.",
     0.0),

    (r"(?i)password\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
     "Hardcoded Password", 259,
     "Move to environment variable. Use secrets manager (Vault, AWS SSM, GCP Secret Manager).",
     3.2),  # entropy check on captured group

    (r"(?i)(?:secret|api_key|apikey|auth_token|access_token)\s*[:=]\s*['\"]([^'\"]{10,})['\"]",
     "Hardcoded Secret", 798,
     "Move to environment variable. Inject at runtime from a secrets manager.",
     3.5),

    (r"[a-zA-Z]{3,10}://[^:@/\s]{2,}:([^@/\s]{6,})@",
     "Credentials in URL", 522,
     "Remove password from URL. Use IAM auth, connection string secrets, or env vars.",
     3.0),
]


def _extract_secret_value(line: str, pattern: str) -> str:
    """Extract the credential value from the matched line for entropy checking."""
    m = re.search(pattern, line, re.IGNORECASE)
    if not m:
        return ""
    # If pattern has a capture group, use it; otherwise use full match
    return m.group(1) if m.lastindex else m.group(0)


def scan_secrets(path: str) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(path)
    extensions = {
        ".py", ".js", ".ts", ".go", ".rs", ".yaml", ".yml",
        ".json", ".env", ".sh", ".tf", ".toml", ".cfg", ".ini",
        ".rb", ".php", ".java", ".kt", ".cs", ".swift",
    }

    for file in root.rglob("*"):
        if not file.is_file() or file.suffix not in extensions or _skip(file):
            continue

        text = _read(file)
        if text is None:
            continue

        is_test = _is_test_file(file)

        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern, title, cwe, remediation, min_entropy in _SECRET_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue

                value = _extract_secret_value(line, pattern)

                # Entropy gate — skip if value looks like a placeholder
                if min_entropy > 0:
                    if is_placeholder(value) or not is_high_entropy(value, min_entropy):
                        continue

                confidence = Confidence.MEDIUM if is_test else Confidence.HIGH

                findings.append(Finding.make(
                    title=title,
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    description=(
                        f"{title} detected in {'test ' if is_test else ''}source code. "
                        f"Entropy: {shannon(value):.2f} bits/char."
                        if value else
                        f"{title} detected in {'test ' if is_test else ''}source code."
                    ),
                    evidence=line.strip()[:120],
                    affected=f"{file}:{line_no}",
                    cwe=cwe,
                    tags=["secrets", "credential-exposure"] + (["test-file"] if is_test else []),
                    remediation=remediation,
                ))

    return findings


# ── Code pattern scanner ────────────────────────────────────────────────────

# (regex, title, severity, CWE, description, remediation, tags, skip_tests)
_CODE_PATTERNS: list[tuple[str, str, Severity, int | None, str, str, list[str], bool]] = [
    (r"\beval\s*\(",
     "Use of eval()", Severity.HIGH, 95,
     "eval() executes arbitrary strings as code. Any attacker-controlled input achieves RCE.",
     "Replace with explicit parsing logic. If dynamic dispatch is needed, use a safe dispatch table.",
     ["injection", "rce"], False),

    (r"\bexec\s*\(",
     "Use of exec()", Severity.HIGH, 95,
     "exec() executes arbitrary code strings. Equivalent to eval() for RCE risk.",
     "Use subprocess with an explicit args list. Never pass user input to exec().",
     ["injection", "rce"], False),

    (r"subprocess\.[a-z_]+\(.*shell\s*=\s*True",
     "subprocess with shell=True", Severity.HIGH, 78,
     "shell=True with any user-controlled input enables OS command injection.",
     "Pass args as a list: subprocess.run(['cmd', arg]). Never build shell strings from input.",
     ["injection", "command-injection"], False),

    (r"(?i)f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\{",
     "SQL Injection via f-string", Severity.HIGH, 89,
     "SQL built with f-strings and user data is injectable. Parameterization is bypassed.",
     "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (id,))",
     ["injection", "sqli"], False),

    (r"pickle\.loads?\s*\(",
     "Insecure Pickle Deserialization", Severity.HIGH, 502,
     "Unpickling untrusted data executes arbitrary code. No safe subset of pickle exists.",
     "Use JSON, MessagePack, or protobuf for untrusted data. Reserve pickle for trusted internal use.",
     ["deserialization"], False),

    (r"\bhashlib\.(md5|sha1)\s*\(",
     "Weak Hash Algorithm (MD5/SHA-1)", Severity.MEDIUM, 327,
     "MD5 and SHA-1 are cryptographically broken. Collisions are practical for both.",
     "Use hashlib.sha256() or hashlib.sha3_256(). For passwords, use bcrypt or argon2.",
     ["crypto", "weak-hash"], True),

    (r"\brandom\.(random|randint|choice|choices|shuffle|sample)\s*\(",
     "Cryptographically Insecure Randomness", Severity.MEDIUM, 338,
     "random module uses Mersenne Twister — predictable given sufficient output.",
     "Use the secrets module for tokens, nonces, keys, and any security-sensitive values.",
     ["crypto", "randomness"], True),

    (r"\bassert\b.*(?:auth|role|permission|admin|is_staff|is_superuser)",
     "Assert Used as Security Gate", Severity.MEDIUM, 617,
     "assert is stripped when Python runs with -O flag. Security checks must not use assert.",
     "Replace with: if not condition: raise PermissionError(...)",
     ["auth"], False),

    (r"(?i)(TODO|FIXME|HACK|XXX).*(?:security|auth|crypto|vuln|injection|secret|bypass)",
     "Security-Relevant TODO", Severity.LOW, None,
     "Unresolved security TODO. Known gap that may be shipped as-is.",
     "Track in issue tracker with severity. Do not ship known security gaps.",
     ["hygiene"], False),

    (r"(?i)verify\s*=\s*False",
     "TLS Certificate Verification Disabled", Severity.HIGH, 295,
     "verify=False disables TLS certificate validation, enabling MITM attacks.",
     "Remove verify=False. If using self-signed certs, provide the CA bundle path instead.",
     ["crypto", "tls"], False),

    (r"(?i)ssl\.CERT_NONE|ssl\._create_unverified_context",
     "SSL Context Without Certificate Verification", Severity.HIGH, 295,
     "CERT_NONE disables peer certificate validation entirely.",
     "Use ssl.create_default_context() which validates by default.",
     ["crypto", "tls"], False),
]


def scan_code(path: str, languages: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(path)
    lang_map: dict[str, set[str]] = {
        "python":     {".py"},
        "javascript": {".js", ".mjs", ".cjs"},
        "typescript": {".ts", ".tsx"},
        "go":         {".go"},
        "rust":       {".rs"},
        "ruby":       {".rb"},
        "java":       {".java"},
    }
    allowed = (
        {ext for lang in languages for ext in lang_map.get(lang.lower(), set())}
        if languages
        else {ext for exts in lang_map.values() for ext in exts}
    )

    for file in root.rglob("*"):
        if not file.is_file() or file.suffix not in allowed or _skip(file):
            continue

        text = _read(file)
        if text is None:
            continue

        is_test = _is_test_file(file)

        for line_no, line in enumerate(text.splitlines(), 1):
            for pat, title, severity, cwe, desc, remediation, tags, skip_tests in _CODE_PATTERNS:
                if is_test and skip_tests:
                    continue
                if re.search(pat, line):
                    confidence = Confidence.MEDIUM if is_test else Confidence.HIGH
                    findings.append(Finding.make(
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        description=desc,
                        evidence=line.strip()[:120],
                        affected=f"{file}:{line_no}",
                        cwe=cwe,
                        tags=tags + (["test-file"] if is_test else []),
                        remediation=remediation,
                    ))

    return findings


# ── Cloud config scanner — CCSP ────────────────────────────────────────────

def scan_cloud_config(path: str) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(path)

    for file in root.rglob("*"):
        if not file.is_file() or _skip(file):
            continue

        text = _read(file)
        if text is None:
            continue

        suffix = file.suffix.lower()
        if suffix == ".tf":
            findings += _terraform(text, str(file))
        elif suffix in (".yaml", ".yml", ".json"):
            findings += _cloudformation(text, str(file))

    return findings


def _terraform(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []

    if re.search(r'acl\s*=\s*["\']public-read', text):
        out.append(Finding.make(
            title="S3 Bucket Publicly Readable",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            description="S3 ACL public-read exposes all objects. Violates CCSP shared-responsibility data controls.",
            evidence='acl = "public-read"', affected=path, cwe=732,
            tags=["cloud", "s3", "data-exposure"],
            remediation="Set acl = \"private\". Enable S3 Block Public Access at account level.",
        ))

    if "aws_s3_bucket" in text and "server_side_encryption_configuration" not in text:
        out.append(Finding.make(
            title="S3 Bucket Without Encryption at Rest",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="No server_side_encryption_configuration block. Data at rest is unencrypted. CCSP CC6.1.",
            evidence="aws_s3_bucket without server_side_encryption_configuration",
            affected=path, cwe=311,
            tags=["cloud", "s3", "encryption"],
            remediation="Add server_side_encryption_configuration with rule.apply_server_side_encryption_by_default.",
        ))

    if re.search(r'"Action"\s*:\s*"\*"|actions\s*=\s*\["\*"\]', text):
        out.append(Finding.make(
            title="IAM Policy Grants Wildcard Actions (*)",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            description="Wildcard IAM action violates least-privilege. Full account compromise if credential is exposed.",
            evidence='"Action": "*"', affected=path, cwe=269,
            tags=["cloud", "iam", "least-privilege"],
            remediation="Enumerate required actions. Run IAM Access Analyzer to generate least-privilege policy.",
        ))

    if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', text):
        out.append(Finding.make(
            title="Security Group Open to 0.0.0.0/0",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="Inbound rule allows all IPs. Exposes service to internet.",
            evidence='cidr_blocks = ["0.0.0.0/0"]', affected=path, cwe=284,
            tags=["cloud", "network", "exposure"],
            remediation="Restrict to known CIDR ranges. Use VPC endpoints or AWS PrivateLink for internal services.",
        ))

    if "aws_s3_bucket" in text and "logging" not in text:
        out.append(Finding.make(
            title="S3 Bucket Without Access Logging",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            description="S3 access logs are required for CISA/CISM audit trails and incident forensics.",
            evidence="aws_s3_bucket without logging block", affected=path, cwe=778,
            tags=["cloud", "s3", "audit-trail"],
            remediation="Add logging { target_bucket = ... target_prefix = ... } block.",
            risk_treatment=RiskTreatment.MITIGATE,
        ))

    if re.search(r"deletion_protection\s*=\s*false", text):
        out.append(Finding.make(
            title="Database Deletion Protection Disabled",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            description="deletion_protection = false allows accidental or malicious database deletion.",
            evidence="deletion_protection = false", affected=path, cwe=284,
            tags=["cloud", "database", "data-integrity"],
            remediation="Set deletion_protection = true for all production databases.",
        ))

    return out


def _cloudformation(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []

    if re.search(r"PublicRead|public-read", text, re.IGNORECASE):
        out.append(Finding.make(
            title="CloudFormation: Public S3 ACL",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            description="CloudFormation sets S3 ACL to public-read.",
            evidence="PublicRead ACL", affected=path, cwe=732,
            tags=["cloud", "cloudformation", "s3", "data-exposure"],
            remediation="Set AccessControl: Private. Add PublicAccessBlockConfiguration.",
        ))

    if re.search(r'"Effect"\s*:\s*"Allow".*?"Action"\s*:\s*"\*"', text, re.DOTALL):
        out.append(Finding.make(
            title="CloudFormation: IAM Wildcard Allow",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            description='IAM policy grants Action: "*" — all actions allowed.',
            evidence='Effect: Allow, Action: "*"', affected=path, cwe=269,
            tags=["cloud", "cloudformation", "iam", "least-privilege"],
            remediation="Enumerate required actions explicitly.",
        ))

    return out


# ── Container / Kubernetes scanner — CCSP cloud-native ────────────────────

def scan_containers(path: str) -> list[Finding]:
    """
    CCSP cloud-native security: Dockerfile and Kubernetes manifest checks.
    Container security is a first-class CCSP concern — shared-responsibility
    model places container hardening firmly in the customer's column.
    """
    findings: list[Finding] = []
    root = Path(path)

    for file in root.rglob("*"):
        if _skip(file):
            continue

        name_lower = file.name.lower()

        if name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
            text = _read(file)
            if text:
                findings += _dockerfile(text, str(file))

        elif file.suffix in (".yaml", ".yml") and not _skip(file):
            text = _read(file)
            if text and _looks_like_k8s(text):
                findings += _kubernetes(text, str(file))

    return findings


def _looks_like_k8s(text: str) -> bool:
    return bool(re.search(r"apiVersion\s*:", text) and re.search(r"kind\s*:", text))


def _dockerfile(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()

    # Running as root
    has_user = any(re.match(r"^\s*USER\s+", l, re.IGNORECASE) for l in lines)
    if not has_user:
        out.append(Finding.make(
            title="Dockerfile: No USER Directive (Running as Root)",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="Container runs as root by default. Container escape becomes full host compromise.",
            evidence="No USER instruction found", affected=path, cwe=250,
            tags=["container", "cloud", "least-privilege"],
            remediation="Add USER nonroot (or specific UID > 0) before the final CMD/ENTRYPOINT.",
        ))

    # Secrets in ENV/ARG
    for i, line in enumerate(lines, 1):
        if re.search(r"(?i)^(ENV|ARG)\s+.*(password|secret|token|key|api_key)\s*=\s*\S+", line):
            val = re.search(r"=\s*(\S+)", line)
            value = val.group(1) if val else ""
            if value and not is_placeholder(value):
                out.append(Finding.make(
                    title="Dockerfile: Secret in ENV/ARG",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    description="Secrets baked into ENV/ARG are visible in image layers and docker inspect.",
                    evidence=line.strip()[:120], affected=f"{path}:{i}", cwe=798,
                    tags=["container", "secrets", "credential-exposure"],
                    remediation="Use Docker secrets, BuildKit --secret, or inject at runtime via orchestrator.",
                ))

    # Using :latest tag
    for i, line in enumerate(lines, 1):
        if re.match(r"^\s*FROM\s+\S+:latest", line, re.IGNORECASE):
            out.append(Finding.make(
                title="Dockerfile: Unpinned :latest Tag",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=":latest is mutable. Supply chain attacks can substitute a malicious image.",
                evidence=line.strip(), affected=f"{path}:{i}", cwe=829,
                tags=["container", "supply-chain"],
                remediation="Pin to a specific digest: FROM image@sha256:...",
            ))

    # ADD instead of COPY (can extract archives — unexpected behavior)
    for i, line in enumerate(lines, 1):
        if re.match(r"^\s*ADD\s+", line, re.IGNORECASE) and not re.search(r"https?://", line):
            out.append(Finding.make(
                title="Dockerfile: ADD Instead of COPY",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                description="ADD silently extracts tar archives, which can overwrite system files unexpectedly.",
                evidence=line.strip(), affected=f"{path}:{i}", cwe=706,
                tags=["container", "hygiene"],
                remediation="Use COPY for local files. Reserve ADD only for remote URLs (and prefer curl + verify).",
            ))

    return out


def _kubernetes(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []

    # Privileged container
    if re.search(r"privileged\s*:\s*true", text):
        out.append(Finding.make(
            title="Kubernetes: Privileged Container",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            description="privileged: true grants the container all Linux capabilities and host device access. Full host escape.",
            evidence="privileged: true", affected=path, cwe=250,
            tags=["container", "cloud", "least-privilege"],
            remediation="Remove privileged: true. Grant only required capabilities via securityContext.capabilities.add.",
        ))

    # hostNetwork
    if re.search(r"hostNetwork\s*:\s*true", text):
        out.append(Finding.make(
            title="Kubernetes: hostNetwork Enabled",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="hostNetwork shares the host's network namespace. Container can bind to host ports and intercept traffic.",
            evidence="hostNetwork: true", affected=path, cwe=284,
            tags=["container", "cloud", "network"],
            remediation="Remove hostNetwork: true. Use ClusterIP Services and proper ingress.",
        ))

    # No securityContext
    if "securityContext" not in text and re.search(r"kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod)", text):
        out.append(Finding.make(
            title="Kubernetes: No securityContext Defined",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            description="Without securityContext, containers run with default (permissive) security settings.",
            evidence="Deployment/Pod without securityContext", affected=path, cwe=250,
            tags=["container", "cloud", "least-privilege"],
            remediation="Add securityContext: { runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false }",
        ))

    # Secrets as environment variables
    if re.search(r"secretKeyRef", text) and re.search(r"env\s*:", text):
        out.append(Finding.make(
            title="Kubernetes: Secret Exposed as Environment Variable",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            description="Secrets in env vars are visible to all processes in the container and logged in crash dumps.",
            evidence="secretKeyRef in env block", affected=path, cwe=312,
            tags=["container", "cloud", "secrets"],
            remediation="Mount secrets as files via volumes instead of env vars. Use a CSI secrets driver.",
            risk_treatment=RiskTreatment.MITIGATE,
        ))

    # Latest image tag in K8s
    if re.search(r"image\s*:\s*\S+:latest", text):
        out.append(Finding.make(
            title="Kubernetes: Container Image Using :latest Tag",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            description=":latest is mutable. Pod restarts may pull a different (potentially malicious) image.",
            evidence="image: ....:latest", affected=path, cwe=829,
            tags=["container", "cloud", "supply-chain"],
            remediation="Pin to a specific digest or immutable tag. Enable ImagePolicyWebhook admission controller.",
        ))

    # No resource limits
    if re.search(r"kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod)", text) and "resources" not in text:
        out.append(Finding.make(
            title="Kubernetes: No Resource Limits",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            description="Without CPU/memory limits, a compromised container can exhaust node resources (DoS).",
            evidence="No resources block found", affected=path, cwe=400,
            tags=["container", "cloud", "availability"],
            remediation="Add resources: { limits: { cpu: '500m', memory: '256Mi' }, requests: {...} }",
            risk_treatment=RiskTreatment.MITIGATE,
        ))

    return out
