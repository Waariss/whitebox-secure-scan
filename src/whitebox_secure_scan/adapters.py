"""Safe local external-tool adapters and result normalizers.

Tool execution remains opt-in. Result import is file-only and never installs a
tool, downloads a database, or contacts a service.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

from .models import Finding
from .redaction import redact
from .subprocess_runner import run_local


@dataclass
class AdapterResult:
    findings: list[Finding]
    errors: list[str]


SUPPORTED = {"semgrep", "gitleaks", "trivy", "bandit", "gosec", "findsecbugs"}


def _severity(value: object) -> str:
    normalized = str(value or "medium").lower()
    return (
        normalized
        if normalized in {"informational", "low", "medium", "high", "critical"}
        else "medium"
    )


def _relative_path(value: object, root: Path | None) -> str:
    path = Path(str(value or "unknown"))
    if root:
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            pass
    return str(path).replace("\\", "/")


def _cwes(value: object) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        values = []
    return [item if str(item).upper().startswith("CWE-") else f"CWE-{item}" for item in values]


def _line(value: object) -> int:
    try:
        return int(str(value or "1").split(":", 1)[0])
    except ValueError:
        return 1


def _external_finding(
    tool: str,
    rule_id: str,
    title: str,
    path: str,
    line: int,
    message: str,
    severity: object,
    confidence: object,
    cwes: object,
) -> Finding:
    confidence_text = str(confidence or "medium").lower()
    score = {"high": 90, "medium": 65, "low": 35}.get(confidence_text, 55)
    safe_path = path.replace("\\", "/")
    stable = hashlib.sha256(f"{tool}:{rule_id}:{safe_path}:{line}:{title}".encode()).hexdigest()[
        :16
    ]
    return Finding(
        id=stable,
        rule_id=f"EXT.{tool.upper()}.{rule_id}",
        title=title or f"{tool} result {rule_id}",
        description=redact(message),
        category="external_tool",
        subcategory="imported-result",
        language="unknown",
        classification="high_confidence_candidate" if score >= 80 else "review_lead",
        confidence_score=score,
        suggested_severity=_severity(severity),
        cwe_ids=_cwes(cwes),
        file_path=safe_path,
        start_line=max(1, int(line or 1)),
        end_line=max(1, int(line or 1)),
        evidence=redact(message),
        analyzer=f"external.{tool}",
        external_tool=tool,
        external_rule_id=rule_id,
        verdict_candidate="high_confidence_candidate" if score >= 80 else "secure_coding_concern",
        parser_used="external-result",
        sink="external tool result",
        sink_detected=True,
        flow_status="sink_only",
        proof_gaps=["Verify the imported result against current source and surrounding controls."],
        recommended_verification_steps=[
            "Confirm the external result and trace the current source-to-sink flow."
        ],
    )


def _semgrep(data: dict, root: Path | None) -> list[Finding]:
    result = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        result.append(
            _external_finding(
                "semgrep",
                item.get("check_id", "unknown"),
                extra.get("message", item.get("check_id", "Semgrep finding")),
                _relative_path(item.get("path"), root),
                item.get("start", {}).get("line", 1),
                extra.get("message", "Imported Semgrep result"),
                extra.get("severity", "medium"),
                metadata.get("confidence", "medium"),
                metadata.get("cwe", []),
            )
        )
    return result


def _gitleaks(data: list, root: Path | None) -> list[Finding]:
    return [
        _external_finding(
            "gitleaks",
            item.get("RuleID", "unknown"),
            item.get("Description", "Potential secret"),
            _relative_path(item.get("File"), root),
            item.get("StartLine", 1),
            item.get("Description", "Imported Gitleaks result"),
            "high",
            "high",
            [],
        )
        for item in data
    ]


def _bandit(data: dict, root: Path | None) -> list[Finding]:
    return [
        _external_finding(
            "bandit",
            item.get("test_id", "unknown"),
            item.get("issue_text", "Bandit finding"),
            _relative_path(item.get("filename"), root),
            item.get("line_number", 1),
            item.get("issue_text", "Imported Bandit result"),
            item.get("issue_severity", "medium"),
            item.get("issue_confidence", "medium"),
            item.get("issue_cwe", {}).get("id", []),
        )
        for item in data.get("results", [])
    ]


def _gosec(data: dict, root: Path | None) -> list[Finding]:
    return [
        _external_finding(
            "gosec",
            item.get("rule_id", item.get("rule", "unknown")),
            item.get("details", "gosec finding"),
            _relative_path(item.get("file"), root),
            _line(item.get("line", "1")),
            item.get("details", "Imported gosec result"),
            item.get("severity", "medium"),
            item.get("confidence", "medium"),
            item.get("cwe", []),
        )
        for item in data.get("Issues", data.get("issues", []))
    ]


def _findsecbugs(data: bytes, root: Path | None) -> list[Finding]:
    findings = []
    for item in ET.fromstring(data).iter("BugInstance"):
        source = next(iter(item.iter("SourceLine")), None)
        findings.append(
            _external_finding(
                "findsecbugs",
                item.get("type", "unknown"),
                item.get("type", "FindSecBugs finding"),
                _relative_path(source.get("sourcepath") if source is not None else "unknown", root),
                _line(source.get("start") if source is not None else 1),
                item.get("type", "Imported FindSecBugs result"),
                item.get("priority", "medium"),
                "medium",
                [],
            )
        )
    return findings


def import_result_file(name: str, path: Path, root: Path | None = None) -> AdapterResult:
    """Import one local JSON/XML result file into the normalized finding model."""
    if name not in SUPPORTED:
        return AdapterResult([], [f"unsupported adapter: {name}"])
    try:
        raw = path.read_bytes()
        if name == "findsecbugs":
            return AdapterResult(_findsecbugs(raw, root), [])
        data = json.loads(raw.decode("utf-8"))
        if name == "semgrep":
            findings = _semgrep(data, root)
        elif name == "gitleaks":
            findings = _gitleaks(data, root)
        elif name == "bandit":
            findings = _bandit(data, root)
        elif name == "gosec":
            findings = _gosec(data, root)
        else:
            findings = []
        return AdapterResult(findings, [])
    except (OSError, UnicodeDecodeError, ValueError, ET.ParseError) as exc:
        return AdapterResult([], [f"{name} import failed: {exc}"])


def run_local_adapter(name: str, root: Path, timeout: int = 30) -> AdapterResult:
    executable = shutil.which(name)
    if name not in SUPPORTED or executable is None:
        return AdapterResult([], [f"adapter unavailable or unsupported: {name}"])
    # Adapters intentionally require explicit integration and never use a shell.
    try:
        proc = run_local(
            [executable, "--version"],
            cwd=root,
            timeout=timeout,
            env={"PATH": str(Path(executable).parent)},
        )
        if proc.returncode != 0:
            return AdapterResult([], [f"{name} exited {proc.returncode}"])
        return AdapterResult([], [])
    except (OSError, TimeoutError, ValueError) as exc:
        return AdapterResult([], [f"{name}: {exc}"])
