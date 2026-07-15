import hashlib
from collections import defaultdict
from typing import Any

from .models import Finding


def _root_id(f: Finding) -> str:
    key = f"{f.rule_id}|{f.sink or ''}|{f.source or ''}|{f.related_callees[0] if f.related_callees else ''}"
    return "RC-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper()


def correlate(findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        rid = _root_id(finding)
        finding.root_cause_id = rid
        finding.instance_of = rid
        groups[rid].append(finding)
    roots = []
    for rid, instances in sorted(groups.items()):
        first = instances[0]
        roots.append(
            {
                "root_cause_id": rid,
                "title": first.title,
                "root_cause_type": first.verdict_candidate,
                "instance_count": len(instances),
                "instances": [x.id for x in instances],
                "canonical_location": {"file_path": first.file_path, "line": first.start_line},
                "shared_sink": first.sink or "",
                "shared_callee": first.related_callees[0] if first.related_callees else "",
                "related_routes": sorted({route for x in instances for route in x.related_routes}),
                "proof_gaps": sorted({gap for x in instances for gap in x.proof_gaps}),
                "counterevidence": sorted({item for x in instances for item in x.counterevidence}),
            }
        )
    return findings, roots


def summaries(findings: list[Finding], roots: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "root_causes": len(roots),
        "instances": len(findings),
        "candidate_findings": sum(
            f.verdict_candidate
            in {
                "confirmed_static_evidence",
                "high_confidence_candidate",
                "runtime_verification_required",
                "secure_coding_concern",
            }
            for f in findings
        ),
        "review_points": sum(
            f.verdict_candidate in {"review_point", "informational_inventory"} for f in findings
        ),
        "test_only_items": sum(f.test_only for f in findings),
        "suppressed_results": sum(f.verdict_candidate == "suppressed" for f in findings),
        "complete_flows": sum(f.flow_status == "complete" for f in findings),
        "partial_flows": sum(f.flow_status == "partial" for f in findings),
        "sink_only": sum(f.flow_status == "sink_only" for f in findings),
    }
