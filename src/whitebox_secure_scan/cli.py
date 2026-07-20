import argparse
import contextlib
import io
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from . import __version__
from .adapters import import_result_file, run_local_adapter
from .analyzer import scan
from .correlation import correlate, summaries
from .code_graph import build_code_graph, enrich_route
from .config import ScanConfig, load_review_config, parse_csv
from .detectors import detect_frameworks, detect_languages
from .reporting import markdown, sarif, write_json
from .repository import inventory_manifests, walk_repository
from .rules import validate_rules
from .parsers import parser_capabilities
from .models import Finding

OUTPUTS = [
    "inventory.json",
    "routes.json",
    "findings.json",
    "findings.sarif",
    "report.md",
    "scan-metadata.json",
    "errors.log",
    "root-causes.json",
    "review-points.json",
    "security-inventory.json",
]


def _lexical_path(path: Path) -> Path:
    """Return an absolute path without resolving symlinks."""
    path = path.expanduser()
    return path if path.is_absolute() else Path.cwd() / path


def _reject_symlink_components(path: Path) -> Path:
    lexical = _lexical_path(path)
    current = lexical
    while True:
        if current.is_symlink():
            raise ValueError("path must not contain symlinks")
        if current == current.parent:
            break
        current = current.parent
    return lexical


def safe_output(root: Path, output: Path, allow_inside: bool = False) -> Path:
    root = root.resolve()
    output = _reject_symlink_components(output).resolve()
    if not allow_inside and (output == root or root in output.parents):
        raise ValueError("output directory must not be inside the target repository")
    current = output
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise ValueError("output path must not contain symlinks")
        current = current.parent
    output.mkdir(parents=True, exist_ok=True)
    return output


def _route_inventory(files, frameworks):
    routes = []
    markers = (
        "app.route",
        "app.get",
        "app.post",
        "app.put",
        "app.delete",
        "router.",
        "@app.get",
        "@app.post",
        "@GetMapping",
        "@PostMapping",
        "@RequestMapping",
        "http.HandleFunc",
        "HandleFunc",
        "router.GET",
        "router.POST",
        "e.GET",
        "app.Get",
    )
    for file in files:
        for line_no, line in enumerate(file.text.splitlines(), 1):
            if any(marker in line for marker in markers):
                method_match = re.search(
                    r"(?i)(get|post|put|patch|delete|options|head)\s*[,\.(]\s*['\"]([^'\"]+)", line
                )
                decorator_match = re.search(
                    r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)",
                    line,
                    re.I,
                )
                java_match = re.search(
                    r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\([^)]*value\s*=\s*['\"]([^'\"]+)",
                    line,
                )
                route_match = decorator_match or method_match
                if route_match:
                    method, route = route_match.groups()
                elif java_match:
                    method, route = "mapping", java_match.group(1)
                else:
                    method, route = None, None
                routes.append(
                    {
                        "method": method.upper() if method else None,
                        "path": route,
                        "framework": next(
                            (x for x in frameworks if x.lower() in line.lower()), None
                        ),
                        "handler": None,
                        "file": str(file.path),
                        "line": line_no,
                        "authentication_middleware": [],
                        "authorization_middleware": [],
                        "roles": [],
                        "permissions": [],
                        "request_parameters": [],
                        "sensitive_operations": [],
                        "database_objects": [],
                        "ownership_checks": [],
                        "tenant_checks": [],
                        "review_notes": "Route syntax observed; metadata is populated only when statically observable.",
                        "evidence": line.strip()[:300],
                    }
                )
    graph = build_code_graph(files)
    return [enrich_route(route, graph) for route in routes]


def _inventory(root, files, walked, frameworks):
    categories: dict[str, list[str]] = {
        "entry_points": [],
        "controllers": [],
        "handlers": [],
        "webhooks": [],
        "background_workers": [],
        "scheduled_jobs": [],
        "message_consumers": [],
        "authentication_components": [],
        "authorization_components": [],
        "database_access": [],
        "file_upload_handlers": [],
        "outbound_http_clients": [],
        "cryptographic_components": [],
        "deployment_files": [],
    }
    for file in files:
        text = file.text.lower()
        target = None
        if any(
            x in text
            for x in (
                "if __name__",
                "func main(",
                "public static void main",
                "createServer",
                "app.listen",
            )
        ):
            target = "entry_points"
        elif any(x in text for x in ("webhook", "@webhook")):
            target = "webhooks"
        elif any(
            x in text for x in ("celery", "cron", "schedule", "background", "consumer", "worker")
        ):
            target = "background_workers"
        elif any(
            x in text
            for x in ("password", "jwt", "authenticate", "authorize", "permission", "role")
        ):
            target = "authentication_components"
        elif any(x in text for x in ("sql", "database", "jdbc", "gorm", "mongoose")):
            target = "database_access"
        elif any(x in text for x in ("upload", "multipart", "multer")):
            target = "file_upload_handlers"
        elif any(x in text for x in ("requests.", "httpx.", "axios", "http.get", "client.do")):
            target = "outbound_http_clients"
        elif any(x in text for x in ("sha256", "sha1", "md5", "cipher", "crypto")):
            target = "cryptographic_components"
        if target:
            categories[target].append(str(file.path))
    categories["deployment_files"] = [
        str(p.relative_to(root))
        for p in root.rglob("*")
        if not p.is_symlink()
        and p.is_file()
        and any(x in p.name.lower() for x in ("docker", "k8s", "deploy", "workflow", "jenkins"))
    ]
    return {
        "repository_root": str(root),
        # Review mode intentionally does not inspect .git or commit history.
        "commit_hash": None,
        "git_history_read": False,
        "scan_scope": "current_working_tree_only",
        "languages": detect_languages(files),
        "frameworks": frameworks,
        "dependency_manifests": inventory_manifests(root),
        "lock_files": [
            x
            for x in inventory_manifests(root)
            if "lock" in x or x.endswith(("go.sum", "requirements.txt"))
        ],
        "build_files": [
            x
            for x in inventory_manifests(root)
            if x.endswith(("Dockerfile", "pom.xml", "build.gradle", "pyproject.toml"))
        ],
        "skipped_files": walked.skipped,
        "parser_errors": walked.parser_errors,
        **categories,
    }


def run_scan(args) -> int:
    root = Path(args.repository).resolve()
    if not root.is_dir():
        raise ValueError("repository must be a directory")
    output = safe_output(root, Path(args.output), args.allow_output_inside)
    config = ScanConfig(
        offline=args.offline,
        redact=args.redact,
        snippets=not args.no_snippets,
        max_snippet_lines=args.max_snippet_lines,
        includes=parse_csv(args.include),
        excludes=parse_csv(args.exclude),
        languages=parse_csv(args.languages),
        frameworks=parse_csv(args.frameworks),
        severities=parse_csv(args.severity),
        min_confidence=args.confidence,
        max_file_size=args.max_file_size,
        timeout=args.timeout,
        no_git_history=args.no_git_history,
        disable_external_tools=args.disable_external_tools,
        external_tools=parse_csv(args.enable_external_tool),
        local_rules=Path(args.local_rules) if args.local_rules else None,
        respect_gitignore=args.respect_gitignore,
        execute_repository_code=False,
        fail_on=args.fail_on,
        production_only=args.production_only,
        include_test_code=args.include_test_code,
        include_test_secrets=args.include_test_secrets,
        include_test_review_points=args.include_test_review_points,
        show_suppressed=args.show_suppressed,
        result_types=parse_csv(args.result_type),
        minimum_evidence_level=args.minimum_evidence_level,
        root_causes_only=args.root_causes_only,
        exclude_inventory=args.exclude_inventory,
        show_review_points=args.show_review_points,
    )
    walked = walk_repository(
        root, set(config.excludes), config.max_file_size, config.respect_gitignore
    )
    if config.includes:
        walked.files = [
            f
            for f in walked.files
            if any(Path(f.path).match(pattern) for pattern in config.includes)
        ]
    frameworks = detect_frameworks(walked.files, root)
    if config.frameworks:
        frameworks = [x for x in frameworks if x in config.frameworks]
    findings = scan(walked.files, config, frameworks[0] if frameworks else None)
    errors = []
    for spec in getattr(args, "import_result", []) or []:
        if "=" not in spec:
            errors.append(f"invalid imported result specification: {spec}; use tool=path")
            continue
        tool, result_path = spec.split("=", 1)
        imported = import_result_file(tool.lower(), Path(result_path), root)
        findings.extend(imported.findings)
        errors.extend(imported.errors)
    if not config.disable_external_tools:
        for tool in config.external_tools:
            result = run_local_adapter(tool, root, config.timeout)
            findings.extend(result.findings)
            errors.extend(result.errors)
    deduplicated: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        deduplicated[(finding.rule_id, finding.file_path, finding.start_line)] = finding
    findings = list(deduplicated.values())
    findings, root_causes = correlate(findings)
    inventory = _inventory(root, walked.files, walked, frameworks)
    routes = _route_inventory(walked.files, frameworks)
    metadata = {
        "scanner": "whitebox-secure-scan",
        "version": __version__,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "target": str(root),
        "files_scanned": len(walked.files),
        "files_skipped": len(walked.skipped),
        "languages": detect_languages(walked.files),
        "frameworks": frameworks,
        "git_history": "not inspected; current repository files only",
        "offline": config.offline,
        "redaction": config.redact,
        "snippets": config.snippets,
        "repository_execution": False,
        "external_tools": list(config.external_tools),
        "imported_results": list(getattr(args, "import_result", []) or []),
        "network": "disabled by design",
        "parser_capabilities": parser_capabilities(),
    }
    write_json(output / "inventory.json", inventory)
    write_json(output / "routes.json", routes)
    write_json(output / "findings.json", [f.to_dict() for f in findings])
    write_json(output / "root-causes.json", root_causes)
    write_json(
        output / "review-points.json",
        [
            f.to_dict()
            for f in findings
            if f.verdict_candidate in {"review_point", "informational_inventory"}
        ],
    )
    write_json(output / "security-inventory.json", inventory)
    write_json(output / "findings.sarif", sarif(findings))
    (output / "report.md").write_text(markdown(findings, inventory, root_causes), encoding="utf-8")
    write_json(output / "scan-metadata.json", metadata)
    (output / "errors.log").write_text("\n".join(errors), encoding="utf-8")
    print(
        json.dumps(
            {
                "target": str(root),
                "files": len(walked.files),
                "findings": len(findings),
                **summaries(findings, root_causes),
                "output": str(output),
            },
            indent=2,
        )
    )
    if args.fail_on and any(f.suggested_severity in {args.fail_on, "critical"} for f in findings):
        return 2
    return 0


def _next_output(path: Path, force: bool) -> Path:
    if not path.exists() or force:
        return path
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return path.with_name(f"{path.name}-{stamp}")


def run_review(args) -> int:
    config_file = load_review_config(Path(args.repository).resolve(), args.config)
    review_cfg = config_file.get("review", {})
    reporting_cfg = config_file.get("reporting", {})
    analysis_cfg = config_file.get("analysis", {})
    test_cfg = config_file.get("test_code", {})
    if args.output == "./whitebox-results" and review_cfg.get("output"):
        args.output = review_cfg["output"]
    args.respect_gitignore = bool(review_cfg.get("respect_gitignore", True))
    args.max_snippet_lines = int(reporting_cfg.get("max_snippet_lines", 3))
    args.max_file_size = int(analysis_cfg.get("maximum_file_size_mb", 2)) * 1_000_000
    args.minimum_evidence_level = int(analysis_cfg.get("minimum_evidence_level", 0))
    args.include_test_secrets = bool(test_cfg.get("include_secrets", True))
    args.include_test_review_points = bool(test_cfg.get("include_review_points", False))
    output = _next_output(Path(args.output), args.force)
    args.output = str(output)
    # Keep the public workflow concise; the low-level scan command retains its
    # machine-readable stdout for compatibility.
    scan_stdout = io.StringIO()
    with contextlib.redirect_stdout(scan_stdout):
        result = run_scan(args)
    summary = output / "SUMMARY.md"
    metadata = json.loads((output / "scan-metadata.json").read_text(encoding="utf-8"))
    roots = json.loads((output / "root-causes.json").read_text(encoding="utf-8"))
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    findings_by_id = {item.get("id"): item for item in findings}
    root_summary: list[str] = []
    for root in roots:
        if root.get("root_cause_type") in {"review_point", "informational_inventory"}:
            continue
        instances = [
            findings_by_id[instance_id]
            for instance_id in root.get("instances", [])
            if instance_id in findings_by_id
        ]
        locations = sorted(
            {f"{item.get('file_path', '?')}:{item.get('start_line', 1)}" for item in instances}
        )
        root_summary.extend(
            [
                f"- `{root.get('root_cause_id')}` — {root.get('title')} ({root.get('root_cause_type')}; {root.get('instance_count')} related instances)",
                f"  - Review locations: {', '.join(f'`{location}`' for location in locations) or 'not available'}",
            ]
        )
    summary.write_text(
        "\n".join(
            [
                "# Whitebox Secure Scan Summary",
                "",
                "Local static white-box secure-code review and triage. Output is not a final pentest report.",
                "",
                "## Repository",
                "",
                f"- Path: `{metadata.get('target', '')}`",
                f"- Languages: {', '.join(metadata.get('languages', {}).keys())}",
                f"- Frameworks: {', '.join(metadata.get('frameworks', []))}",
                f"- Instances: {len(findings)}",
                f"- Root causes: {len(roots)}",
                "",
                "## Scope",
                "",
                "- Current repository files only",
                "- Git commit history not inspected",
                "- No target code execution",
                "",
                "## Candidate root causes",
                "",
                *root_summary,
                "",
                "## Review points",
                "",
                *[
                    f"- `{x.get('id')}` — {x.get('title')}"
                    f" — `{x.get('file_path', '?')}:{x.get('start_line', 1)}`"
                    for x in findings
                    if x.get("verdict_candidate") in {"review_point", "informational_inventory"}
                ],
                "",
                "Instances are retained in `findings.json` and detailed `report.md` for verification.",
                "",
                "## Limitations",
                "",
                "Static analysis only. No runtime validation, target execution, network access, or source upload. Independent verification is required.",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    # The primary review workflow intentionally keeps only human/AI review
    # inputs. Low-level inventory, SARIF, metadata, and handoff packaging stay
    # available through the advanced compatibility commands.
    for name in (
        "inventory.json",
        "security-inventory.json",
        "routes.json",
        "scan-metadata.json",
        "findings.sarif",
    ):
        extra = output / name
        if extra.is_file():
            extra.unlink()
    errors = output / "errors.log"
    if errors.is_file() and not errors.read_text(encoding="utf-8").strip():
        errors.unlink()
    candidate_count = sum(
        x.get("verdict_candidate")
        in {
            "confirmed_static_evidence",
            "high_confidence_candidate",
            "runtime_verification_required",
            "secure_coding_concern",
        }
        for x in findings
    )
    review_count = sum(
        x.get("verdict_candidate") in {"review_point", "informational_inventory"} for x in findings
    )
    if not args.quiet:
        languages = ", ".join(metadata.get("languages", {}).keys()) or "none detected"
        frameworks = ", ".join(metadata.get("frameworks", [])) or "none detected"
        print(f"whitebox-secure-scan {__version__}")
        print("Local static white-box review\n")
        print("Safety")
        print("  Network           disabled")
        print("  External AI       disabled")
        print("  Target execution  disabled")
        print("  Source upload     disabled\n")
        print("Repository")
        print(f"  Path        {args.repository}")
        print(f"  Languages   {languages}")
        print(f"  Frameworks  {frameworks}")
        print(f"  Files       {metadata.get('files_scanned', 'see inventory')}\n")
        print("  History     current repository files only\n")
        print("Review")
        print("  ✓ Inventory")
        print("  ✓ Route mapping")
        print("  ✓ Security analysis")
        print("  ✓ Evidence classification")
        print("  ✓ Root-cause grouping")
        print("  ✓ Report generation\n")
        print("Results")
        print(f"  Candidate root causes  {len(roots):>4}")
        print(f"  Related instances      {len(findings):>4}")
        print(f"  Review leads           {candidate_count:>4}")
        print(f"  Review points          {review_count:>4}")
        print("\nReport:")
        print(f"  {summary.resolve()}")
        print("\nScanner output is not a final pentest report.")
        print("Candidates require independent verification.")
    elif result:
        print(f"Review completed with status {result}. Report: {summary.resolve()}")
    # Public review semantics: only candidate concerns produce exit code 1.
    return 1 if candidate_count else result


def run_version() -> int:
    print(f"whitebox-secure-scan {__version__}")
    return 0


def make_parser():
    parser = argparse.ArgumentParser(
        prog="whitebox-secure-scan",
        description="Offline white-box secure-code triage for penetration testers. Read-only; no AI, network, or source upload.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    parser.usage = (
        "whitebox-secure-scan {review,sample-unreported,compare,doctor,version,rules} ..."
    )
    review = sub.add_parser("review", help="run a white-box secure-code triage review")
    review.add_argument("repository")
    review.add_argument("--output", default="./whitebox-results")
    review.add_argument("--format", choices=["all", "markdown", "json", "sarif"], default="all")
    review.add_argument("--quiet", action="store_true")
    review.add_argument("--verbose", action="store_true")
    review.add_argument("--no-color", action="store_true")
    review.add_argument("--force", action="store_true")
    review.add_argument("--config")
    review.add_argument(
        "--import-result",
        action="append",
        default=[],
        metavar="TOOL=PATH",
        help="import a local Semgrep/Gitleaks/Bandit/gosec/FindSecBugs result",
    )
    review.add_argument(
        "--current-code-only",
        action="store_true",
        default=True,
        help="inspect the current repository files only; Git history is never scanned",
    )
    review.set_defaults(
        func=run_review,
        offline=True,
        redact=True,
        no_snippets=False,
        max_snippet_lines=3,
        include=None,
        exclude=None,
        languages=None,
        frameworks=None,
        severity=None,
        confidence=0,
        max_file_size=2_000_000,
        timeout=30,
        no_git_history=True,
        disable_external_tools=True,
        enable_external_tool=None,
        local_rules=None,
        respect_gitignore=True,
        no_execute_repository_code=True,
        allow_output_inside=False,
        production_only=False,
        include_test_code=False,
        include_test_secrets=True,
        include_test_review_points=False,
        show_suppressed=False,
        result_type=None,
        minimum_evidence_level=0,
        root_causes_only=False,
        exclude_inventory=False,
        show_review_points=True,
        fail_on=None,
    )
    scan_p = sub.add_parser("scan", help=argparse.SUPPRESS, description=argparse.SUPPRESS)
    scan_p.add_argument("repository")
    scan_p.add_argument("--output", required=True)
    scan_p.add_argument("--offline", action=argparse.BooleanOptionalAction, default=True)
    scan_p.add_argument("--redact", action=argparse.BooleanOptionalAction, default=True)
    scan_p.add_argument("--no-snippets", action="store_true")
    scan_p.add_argument("--max-snippet-lines", type=int, default=3)
    scan_p.add_argument("--include", action="append")
    scan_p.add_argument("--exclude", action="append")
    scan_p.add_argument("--languages")
    scan_p.add_argument("--frameworks")
    scan_p.add_argument("--severity", action="append")
    scan_p.add_argument("--confidence", type=int, default=0)
    scan_p.add_argument("--max-file-size", type=int, default=2_000_000)
    scan_p.add_argument("--timeout", type=int, default=30)
    scan_p.add_argument("--fail-on", choices=["informational", "low", "medium", "high", "critical"])
    scan_p.add_argument("--no-git-history", action="store_true", default=True)
    scan_p.add_argument("--disable-external-tools", action="store_true", default=True)
    scan_p.add_argument("--enable-external-tool", action="append")
    scan_p.add_argument("--local-rules")
    scan_p.add_argument("--respect-gitignore", action="store_true")
    scan_p.add_argument("--no-execute-repository-code", action="store_true", default=True)
    scan_p.add_argument("--allow-output-inside", action="store_true")
    scan_p.add_argument("--production-only", action="store_true")
    scan_p.add_argument("--include-test-code", action="store_true")
    scan_p.add_argument(
        "--include-test-secrets", action=argparse.BooleanOptionalAction, default=True
    )
    scan_p.add_argument("--include-test-review-points", action="store_true")
    scan_p.add_argument("--show-suppressed", action="store_true")
    scan_p.add_argument("--result-type", action="append")
    scan_p.add_argument("--minimum-evidence-level", type=int, default=0)
    scan_p.add_argument("--root-causes-only", action="store_true")
    scan_p.add_argument("--exclude-inventory", action="store_true")
    scan_p.add_argument("--show-review-points", action=argparse.BooleanOptionalAction, default=True)
    scan_p.add_argument("--import-result", action="append", default=[])
    scan_p.set_defaults(func=run_scan)
    inv = sub.add_parser("inventory", help=argparse.SUPPRESS, description=argparse.SUPPRESS)
    inv.add_argument("repository")
    inv.add_argument("--output", required=True)
    inv.set_defaults(func=lambda a: run_inventory(a))
    rep = sub.add_parser("report", help=argparse.SUPPRESS, description=argparse.SUPPRESS)
    rep.add_argument("findings")
    rep.add_argument("--output", required=True)
    rep.set_defaults(func=lambda a: run_report(a))
    hand = sub.add_parser("handoff", help=argparse.SUPPRESS, description=argparse.SUPPRESS)
    hand.add_argument("results")
    hand.add_argument("--output", required=True)
    hand.set_defaults(func=lambda a: run_handoff(a))
    sample = sub.add_parser(
        "sample-unreported", help="sample security-sensitive files without candidates"
    )
    sample.add_argument("results")
    sample.add_argument("--repository", required=True)
    sample.add_argument("--count", type=int, default=20)
    sample.add_argument("--output", required=True)
    sample.set_defaults(func=lambda a: run_sample_unreported(a))
    compare = sub.add_parser("compare", help="compare two scan result directories")
    compare.add_argument("old_results")
    compare.add_argument("new_results")
    compare.add_argument("--output", required=True)
    compare.set_defaults(func=lambda a: run_compare(a))
    sub.add_parser("doctor", help="check local scanner capabilities").set_defaults(
        func=lambda a: run_doctor()
    )
    sub.add_parser("version", help="show package version").set_defaults(
        func=lambda a: run_version()
    )
    sub.add_parser(
        "verify-config", help=argparse.SUPPRESS, description=argparse.SUPPRESS
    ).set_defaults(func=lambda a: run_verify_config())
    rules = sub.add_parser("rules", help="rule utilities")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    rv = rules_sub.add_parser("validate")
    rv.add_argument("rules_directory")
    rv.set_defaults(func=lambda a: run_rules_validate(a))
    hidden = {"scan", "inventory", "report", "handoff", "verify-config"}
    sub._choices_actions[:] = [
        action for action in sub._choices_actions if action.dest not in hidden
    ]
    sub.metavar = "{review,sample-unreported,compare,doctor,version,rules}"
    return parser


def run_inventory(args):
    root = Path(args.repository).resolve()
    if not root.is_dir():
        raise ValueError("repository must be a directory")
    output = safe_output(root, Path(args.output))
    walked = walk_repository(root)
    write_json(
        output / "inventory.json",
        _inventory(root, walked.files, walked, detect_frameworks(walked.files, root)),
    )
    print(output / "inventory.json")
    return 0


def run_report(args):
    findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    output = _reject_symlink_components(Path(args.output)).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# White-box secure coding findings",
        "",
        "Findings are review leads and require independent verification.",
        "",
    ]
    for item in findings:
        lines.extend(
            [
                f"## {item.get('title', 'Untitled finding')}",
                f"- Rule: `{item.get('rule_id', '')}`",
                f"- Classification: `{item.get('classification', 'review_lead')}`",
                f"- Severity: `{item.get('suggested_severity', 'informational')}`",
                f"- Location: `{item.get('file_path', '')}:{item.get('start_line', 1)}`",
                f"- Verification: {item.get('recommended_verification_steps', ['Review surrounding control flow.'])}",
                "",
            ]
        )
    output.write_text("\n".join(lines), encoding="utf-8")
    return 0


def run_handoff(args):
    source = Path(args.results).resolve()
    if not source.is_dir():
        raise ValueError("results directory does not exist")
    dest = _reject_symlink_components(Path(args.output)).resolve()
    if (dest == source or source in dest.parents) and dest.name != "ai-handoff":
        raise ValueError("handoff output must not be inside the results directory")
    dest.mkdir(parents=True, exist_ok=True)
    selected = [
        "inventory.json",
        "security-inventory.json",
        "routes.json",
        "findings.json",
        "root-causes.json",
        "review-points.json",
        "scan-metadata.json",
        "errors.log",
    ]
    for name in selected:
        source_file = source / name
        if source_file.is_file():
            shutil.copyfile(source_file, dest / name)
    findings = (
        json.loads((source / "findings.json").read_text(encoding="utf-8"))
        if (source / "findings.json").is_file()
        else []
    )
    root_file = source / "root-causes.json"
    roots = json.loads(root_file.read_text(encoding="utf-8")) if root_file.is_file() else []
    requests = [
        {
            "root_cause_id": root.get("root_cause_id"),
            "priority": "high"
            if root.get("root_cause_type")
            in {"high_confidence_candidate", "confirmed_static_evidence"}
            else "normal",
            "requested_context": [
                {
                    "path": findings_by_id[i].get("file_path", ""),
                    "reason": "Verify the canonical source-to-sink flow.",
                }
                for i in root.get("instances", [])
                if (findings_by_id := {x.get("id"): x for x in findings}).get(i)
            ],
        }
        for root in roots
    ]
    if not roots:
        requests = [
            {
                "finding_id": x.get("id", ""),
                "file_path": x.get("file_path", ""),
                "line_range": [x.get("start_line", 1), x.get("end_line", 1)],
                "related_callers_or_callees": x.get("related_callers", [])
                + x.get("related_callees", []),
                "related_security_components": x.get("related_routes", []),
                "reason": "Verify the partial static evidence and surrounding controls.",
                "proof_gaps": x.get("proof_gaps", []),
                "counterevidence": x.get("counterevidence", []),
                "minimum_context_required": [
                    "Relevant caller/callee",
                    "Authentication/authorization configuration",
                    "Sink-side validation and serving behavior",
                ],
            }
            for x in findings
        ]
    write_json(dest / "context-request.json", requests)
    (dest / "AI_REVIEW_PROMPT.md").write_text(
        "# Internal AI review\n\nTreat every finding as a review lead. Verify control flow and do not assign confirmed status without evidence. No source files are included by default.\n",
        encoding="utf-8",
    )
    (dest / "HANDOFF_README.md").write_text(
        "# Internal AI handoff\n\nThis package contains normalized findings and minimum context requests only. Review findings with an approved internal AI system and security engineer.\n",
        encoding="utf-8",
    )
    return 0


def run_sample_unreported(args):
    root = Path(args.repository).resolve()
    result_dir = Path(args.results).resolve()
    reported = {
        x.get("file_path")
        for x in json.loads((result_dir / "findings.json").read_text(encoding="utf-8"))
    }
    walked = walk_repository(root)
    keywords = (
        "auth",
        "controller",
        "service",
        "middleware",
        "upload",
        "http",
        "crypto",
        "log",
        "file",
        "db",
        "repository",
    )
    selected = [
        str(f.path)
        for f in walked.files
        if str(f.path) not in reported
        and any(k in str(f.path).lower() or k in f.text.lower() for k in keywords)
    ][: args.count]
    dest = _reject_symlink_components(Path(args.output)).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    write_json(
        dest / "negative-sample.json",
        [
            {"file_path": p, "reason": "security-sensitive file with no candidate finding"}
            for p in selected
        ],
    )
    (dest / "AI_NEGATIVE_REVIEW_PROMPT.md").write_text(
        "# Negative review sample\n\nReview the listed files for false negatives. No source files are copied by default.\n",
        encoding="utf-8",
    )
    return 0


def run_compare(args):
    old = Path(args.old_results).resolve()
    new = Path(args.new_results).resolve()

    def load(path):
        return (
            json.loads((path / "findings.json").read_text(encoding="utf-8"))
            if (path / "findings.json").is_file()
            else []
        )

    old_items, new_items = load(old), load(new)
    old_ids, new_ids = {x.get("id") for x in old_items}, {x.get("id") for x in new_items}
    out = [
        "# Scan comparison",
        "",
        f"Old instances: {len(old_items)}",
        f"New instances: {len(new_items)}",
        f"Added instances: {len(new_ids - old_ids)}",
        f"Removed instances: {len(old_ids - new_ids)}",
        "",
        "## Classification changes",
        "",
    ]
    old_map, new_map = {x.get("id"): x for x in old_items}, {x.get("id"): x for x in new_items}
    for fid in sorted(old_ids & new_ids):
        if old_map[fid].get("classification") != new_map[fid].get("classification"):
            out.append(
                f"- `{fid}`: `{old_map[fid].get('classification')}` → `{new_map[fid].get('classification')}`"
            )
    output = _reject_symlink_components(Path(args.output)).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0


def run_doctor():
    import shutil as _shutil

    data = {
        "status": "ok",
        "package_version": __version__,
        "python": sys.version.split()[0],
        "offline_default": True,
        "repository_execution": False,
        "output_write_permissions": os.access(Path.cwd(), os.W_OK),
        "external_tools_default": False,
        "built_in_rules": (Path(__file__).with_name("rules.yaml")).is_file(),
        "parser": parser_capabilities(),
        "optional_tools": {
            name: _shutil.which(name) is not None
            for name in ("semgrep", "gitleaks", "bandit", "gosec", "findsecbugs")
        },
    }
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def run_verify_config():
    checks = {
        "required_outputs": OUTPUTS,
        "redaction_default": True,
        "offline_default": True,
        "repository_execution": False,
        "built_in_rules": (Path(__file__).with_name("rules.yaml")).is_file(),
    }
    valid = (
        checks["built_in_rules"]
        and checks["redaction_default"]
        and checks["offline_default"]
        and not checks["repository_execution"]
    )
    print(json.dumps({"status": "ok" if valid else "invalid", **checks}, indent=2))
    return 0 if valid else 2


def run_rules_validate(args):
    good, errors = validate_rules(Path(args.rules_directory))
    print(json.dumps({"valid": good, "errors": errors}, indent=2))
    return 0 if good else 2


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in {
        "scan",
        "inventory",
        "report",
        "handoff",
        "verify-config",
    }:
        print(
            "This command is deprecated. Use: whitebox-secure-scan review <repository>",
            file=sys.stderr,
        )
    args = make_parser().parse_args()
    try:
        raise SystemExit(args.func(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
