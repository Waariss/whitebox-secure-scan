import json
from pathlib import Path
from . import __version__
from .models import Finding


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sarif(findings: list[Finding]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "whitebox-secure-scan", "version": __version__}},
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": "error"
                        if f.suggested_severity in {"high", "critical"}
                        else "warning",
                        "message": {"text": f.title + ": " + f.description},
                        "properties": {
                            "verdict_candidate": f.verdict_candidate,
                            "code_surface": f.code_surface,
                            "source": f.source,
                            "sink": f.sink,
                            "data_flow": f.data_flow,
                            "proof_gaps": f.proof_gaps,
                            "counterevidence": f.counterevidence,
                            "parser_used": f.parser_used,
                            "exact_invoked_api": f.exact_invoked_api,
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file_path},
                                    "region": {"startLine": f.start_line, "endLine": f.end_line},
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }


def markdown(
    findings: list[Finding], inventory: dict, root_causes: list[dict] | None = None
) -> str:
    root_causes = root_causes or []
    candidates = [
        f
        for f in findings
        if f.verdict_candidate not in {"review_point", "informational_inventory", "suppressed"}
    ]
    review_points = [
        f for f in findings if f.verdict_candidate in {"review_point", "informational_inventory"}
    ]
    out = [
        "# White-box secure coding triage report",
        "",
        "whitebox-secure-scan is a local static secure-code triage and reviewer-assistance tool. Every candidate requires independent internal-AI and security-engineer verification.",
        "",
        f"Root causes: {len(root_causes)} | Instances: {len(findings)} | Review leads: {len(candidates)} | Review points: {len(review_points)}",
        "",
    ]
    sections = (("Candidate review leads", candidates), ("Review points", review_points))
    for heading, items in sections:
        out += [f"## {heading}", ""]
        for f in sorted(items, key=lambda x: (-x.confidence_score, x.file_path, x.start_line)):
            out += [
                f"### {f.title}",
                f"- **Severity:** {f.suggested_severity} | **Type:** {f.verdict_candidate} | **Confidence:** {f.confidence_score}",
                f"- **Location:** `{f.file_path}:{f.start_line}` | **Root cause:** `{f.root_cause_id or 'unassigned'}`",
                f"- **Rule:** `{f.rule_id}` | **Code surface:** `{f.code_surface}` | **Flow:** `{f.flow_status}`",
                f"- **Why raised:** {f.description}",
                f"- **Source → sink:** `{f.source or 'unknown'}` → `{f.sink or 'unknown'}`",
                f"- **Observed controls:** {', '.join(f.observed_controls) or 'None observed.'}",
                f"- **Proof gaps:** {', '.join(f.proof_gaps) or 'None recorded.'}",
                f"- **Counterevidence:** {', '.join(f.counterevidence) or 'None recorded.'}",
                f"- **Reviewer action:** {f.recommended_verification_steps[0] if f.recommended_verification_steps else 'Trace the surrounding source-to-sink flow.'}",
                f"- **Evidence:** `{f.evidence}`",
                "",
            ]
    out += ["## Root causes", ""]
    for root in root_causes:
        out += [
            f"- `{root['root_cause_id']}`: {root['title']} ({root['instance_count']} instances)",
            "",
        ]
    return "\n".join(out)
