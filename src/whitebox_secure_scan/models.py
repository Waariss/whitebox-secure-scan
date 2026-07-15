from dataclasses import asdict, dataclass, field
from typing import Any

CLASSIFICATIONS = {
    "confirmed_candidate",
    "informational_inventory",
    "informational",
    "review_point",
    "secure_coding_concern",
    "review_lead",
    "high_confidence_candidate",
    "runtime_verification_required",
    "confirmed_static_evidence",
    "false_positive_candidate",
    "suppressed",
}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
VERIFICATION = {
    "pending",
    "under_review",
    "confirmed",
    "false_positive",
    "accepted_risk",
    "remediated",
}


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    description: str
    category: str
    subcategory: str
    language: str
    framework: str | None = None
    classification: str = "review_lead"
    confidence_score: int = 0
    suggested_severity: str = "informational"
    cwe_ids: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    file_path: str = ""
    start_line: int = 1
    end_line: int = 1
    function: str | None = None
    class_name: str | None = None
    route: str | None = None
    source: str | None = None
    sink: str | None = None
    data_flow: list[str] = field(default_factory=list)
    observed_controls: list[str] = field(default_factory=list)
    missing_or_questionable_controls: list[str] = field(default_factory=list)
    attacker_requirements: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    potential_impact: str = "Requires manual verification."
    evidence: str = ""
    false_positive_conditions: list[str] = field(default_factory=list)
    recommended_verification_steps: list[str] = field(default_factory=list)
    recommended_remediation: str = (
        "Review the surrounding control flow and use the framework's safe API."
    )
    analyzer: str = "generic"
    external_tool: str | None = None
    external_rule_id: str | None = None
    verification_status: str = "pending"
    verification_notes: str = ""
    confirmed_severity: str | None = None
    false_positive_reason: str | None = None
    remediation_status: str = "open"
    verdict_candidate: str = "cannot_determine"
    code_surface: str = "unknown"
    reachability: str = "unknown"
    transformations: list[str] = field(default_factory=list)
    proof_gaps: list[str] = field(default_factory=list)
    counterevidence: list[str] = field(default_factory=list)
    parser_used: str = "lexical"
    syntax_node_type: str | None = None
    invocation_detected: bool = False
    declaration_detected: bool = False
    comment_context: str = "active_code"
    test_surface: bool = False
    exact_invoked_api: str | None = None
    related_routes: list[str] = field(default_factory=list)
    related_callers: list[str] = field(default_factory=list)
    related_callees: list[str] = field(default_factory=list)
    sensitive_value: str | None = None
    logging_sink: str | None = None
    masking_detected: bool = False
    redaction_detected: bool = False
    structured_logging: bool = False
    missing_controls: list[str] = field(default_factory=list)
    rule_family: str | None = None
    matched_construct: str | None = None
    source_detected: bool = False
    sink_detected: bool = False
    flow_status: str = "unresolved"
    controls_checked: list[str] = field(default_factory=list)
    elevation_reason: str = ""
    suppression_reason: str | None = None
    cwe_mapping_reason: str = ""
    evidence_level: int = 0
    evidence_score: int = 0
    evidence_completeness: dict[str, bool] = field(default_factory=dict)
    production_reachability: str = "unknown"
    test_only: bool = False
    generated: bool = False
    demo: bool = False
    utility: bool = False
    configuration: bool = False
    migration: bool = False
    root_cause_id: str | None = None
    instance_of: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["class_name"] = value.pop("class_name")
        return value
