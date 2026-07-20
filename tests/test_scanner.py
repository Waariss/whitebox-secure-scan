import json
from pathlib import Path
import textwrap
from whitebox_secure_scan.adapters import import_result_file
from whitebox_secure_scan.analyzer import scan
from whitebox_secure_scan.code_graph import build_code_graph
from whitebox_secure_scan.cli import make_parser
from whitebox_secure_scan.config import ScanConfig
from whitebox_secure_scan.parsers import parse, parser_capabilities
from whitebox_secure_scan.repository import walk_repository
from whitebox_secure_scan.reporting import markdown, sarif
from whitebox_secure_scan.rules import load_rules, validate_rules
from whitebox_secure_scan.java_analyzer import strip_java_comments
from whitebox_secure_scan.javascript_analyzer import strip_js_comments

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_help_and_subcommands():
    parser = make_parser()
    assert "scan" in parser.format_help()
    assert parser.parse_args(["doctor"]).command == "doctor"


def test_parser_capability_and_lexical_fallback(tmp_path: Path):
    source = tmp_path / "sample.java"
    source.write_text("class Sample { void run() {} }", encoding="utf-8")
    file = walk_repository(tmp_path).files[0]
    result = parse(file)
    assert result.parser_used in {"lexical-fallback", "tree-sitter.java"}
    capabilities = parser_capabilities()
    assert capabilities["python_ast"] is True
    assert "javascript" in capabilities["languages"]


def test_bounded_route_graph_adds_handler_and_callees(tmp_path: Path):
    source = tmp_path / "app.js"
    source.write_text(
        textwrap.dedent(
            """
            function listUsers(req, res) {
                loadUsers();
                res.json([]);
            }
            app.get('/users', listUsers);
            """
        ),
        encoding="utf-8",
    )
    graph = build_code_graph(walk_repository(tmp_path).files)
    route = graph.routes[0]
    assert route["method"] == "GET"
    assert route["path"] == "/users"
    assert route["handler"] == "listUsers"
    assert "loadUsers" in graph.symbols[0].calls


def test_semgrep_result_import_is_normalized_and_redacted(tmp_path: Path):
    result = tmp_path / "semgrep.json"
    result.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "javascript.lang.security.detect-eval",
                        "path": "src/app.js",
                        "start": {"line": 12},
                        "extra": {
                            "message": "dynamic evaluation with token=synthetic-token-value-12345",
                            "severity": "ERROR",
                            "metadata": {"confidence": "HIGH", "cwe": ["CWE-95"]},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    imported = import_result_file("semgrep", result, tmp_path)
    assert not imported.errors
    assert len(imported.findings) == 1
    finding = imported.findings[0]
    assert finding.external_tool == "semgrep"
    assert finding.external_rule_id == "javascript.lang.security.detect-eval"
    assert finding.file_path == "src/app.js"
    assert finding.start_line == 12
    assert "synthetic-token-value-12345" not in finding.description


def test_synthetic_vulnerable_and_safe_cases():
    vulnerable = walk_repository(FIXTURES / "vulnerable")
    findings = scan(vulnerable.files, ScanConfig())
    rules = {f.rule_id for f in findings}
    assert {"WB.EXEC.DYNAMIC", "WB.SECRET.HARDCODED", "WB.SSRF.OUTBOUND_REQUEST"} <= rules
    safe = scan(walk_repository(FIXTURES / "safe").files, ScanConfig())
    assert not any(f.rule_id == "WB.SECRET.HARDCODED" for f in safe)


def test_stable_ids_and_deduplication():
    files = walk_repository(FIXTURES / "vulnerable").files
    a = scan(files, ScanConfig())
    b = scan(files, ScanConfig())
    assert [x.id for x in a] == [x.id for x in b]
    assert len({(x.rule_id, x.file_path, x.start_line) for x in a}) == len(a)


def test_safety_limits_and_symlink(tmp_path: Path):
    (tmp_path / "huge.py").write_bytes(b"x" * 100)
    (tmp_path / "bad.py").write_bytes(b"\0binary")
    (tmp_path / "link.py").symlink_to(FIXTURES / "vulnerable" / "python_app.py")
    result = walk_repository(tmp_path, max_file_size=20)
    assert not result.files
    assert any(x["reason"] == "symlink not followed" for x in result.skipped)


def test_redaction_and_no_snippets():
    files = walk_repository(FIXTURES / "vulnerable").files
    findings = scan(files, ScanConfig())
    serialized = json.dumps([f.to_dict() for f in findings])
    assert "synthetic-token-value-12345" not in serialized
    assert "synthetic-token" not in serialized
    assert all(f.evidence for f in findings)
    assert all(not f.evidence for f in scan(files, ScanConfig(snippets=False)))


def test_sarif_shape():
    data = sarif(scan(walk_repository(FIXTURES / "vulnerable").files, ScanConfig()))
    assert data["version"] == "2.1.0"
    assert isinstance(data["runs"][0]["results"], list)


def test_markdown_includes_reviewer_guidance():
    findings = scan(walk_repository(FIXTURES / "java_pilot").files, ScanConfig())
    report = markdown(findings, {}, [])
    assert "**Why raised:**" in report
    assert "**Observed controls:**" in report
    assert "**Reviewer action:**" in report
    assert "```text" in report


def test_rules_and_malformed_source(tmp_path: Path):
    assert load_rules(Path("rules"))
    assert validate_rules(Path("rules"))[0]
    assert not validate_rules(tmp_path / "missing")[0]
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    result = walk_repository(tmp_path)
    assert result.files
    assert scan(result.files, ScanConfig()) == []


def test_java_pilot_false_positive_regressions():
    result = walk_repository(FIXTURES / "java_pilot")
    findings = scan(result.files, ScanConfig(languages=("java",)))
    by_file = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, set()).add(finding.rule_id)
    assert by_file["vulnerable.java"] >= {
        "WB.EXEC.DYNAMIC",
        "WB.SQL.RAW_CONSTRUCTION",
        "WB.UPLOAD.UNSAFE",
        "WB.FILE.PATH_INPUT",
        "WB.DESERIALIZATION.UNSAFE",
        "WB.LOG.SENSITIVE_DATA",
        "WB.SECRET.HARDCODED",
    }
    # The file contains harmless API references plus one deliberate sensitive
    # runtime logging example; only the latter should be reported as CWE-532.
    assert by_file.get("false_positives.java", set()) == {"WB.LOG.SENSITIVE_DATA"}
    assert by_file.get("secure.java", set()) == set()
    assert all(
        f.code_surface == "test" and f.test_surface
        for f in findings
        if f.file_path == "vulnerable.java"
    )
    logging = [f for f in findings if f.rule_id == "WB.LOG.SENSITIVE_DATA"]
    assert logging and logging[0].logging_sink and logging[0].sensitive_value
    serialized = json.dumps([f.to_dict() for f in findings])
    assert "AKIA1234567890ABCDEF" not in serialized
    assert "synthetic-secret-key" not in serialized


def test_java_comment_stripping_preserves_string_literals():
    source = 'String text = "// not a comment"; /* ignored */ Runtime.getRuntime().exec(x);'
    stripped = strip_java_comments(source)
    assert '"// not a comment"' in stripped
    assert "Runtime.getRuntime().exec(x);" in stripped


def test_java_secret_logging_and_path_classification_are_distinct():
    findings = scan(
        walk_repository(FIXTURES / "java_pilot").files,
        ScanConfig(languages=("java",)),
    )
    logging = [f for f in findings if f.rule_id == "WB.LOG.SENSITIVE_DATA"]
    secrets = [f for f in findings if f.rule_id == "WB.SECRET.HARDCODED"]
    paths = [f for f in findings if f.rule_id == "WB.FILE.PATH_INPUT"]
    assert logging and all("CWE-532" in f.cwe_ids for f in logging)
    assert all(f.cwe_ids == ["CWE-798"] for f in secrets)
    assert all(f.file_path != "false_positives.java" for f in secrets)
    assert paths and all(f.verdict_candidate == "review_point" for f in paths)
    assert all(f.cwe_ids == [] for f in paths)


def test_java_runtime_secret_logging_is_not_hardcoded_secret():
    findings = scan(
        walk_repository(FIXTURES / "java_pilot").files,
        ScanConfig(languages=("java",)),
    )
    runtime_logs = [
        finding
        for finding in findings
        if finding.file_path == "false_positives.java"
        and finding.rule_id == "WB.LOG.SENSITIVE_DATA"
    ]
    assert runtime_logs and all(finding.cwe_ids == ["CWE-532"] for finding in runtime_logs)
    assert not any(
        finding.file_path == "false_positives.java" and finding.rule_id == "WB.SECRET.HARDCODED"
        for finding in findings
    )


def test_java_batch_csv_generation_is_not_an_upload_flow():
    findings = scan(
        walk_repository(FIXTURES / "java_pilot").files,
        ScanConfig(languages=("java",)),
    )
    assert not any(
        finding.file_path == "false_positives.java"
        and finding.rule_id in {"WB.UPLOAD.UNSAFE", "WB.UPLOAD.ORIGINAL_FILENAME"}
        for finding in findings
    )


def test_java_multipart_utility_without_endpoint_is_only_a_review_point(tmp_path: Path):
    utility = tmp_path / "src" / "main" / "java" / "util"
    utility.mkdir(parents=True)
    (utility / "FileUtils.java").write_text(
        """
        import java.io.File;
        import org.springframework.web.multipart.MultipartFile;
        class FileUtils {
            File multipartToFile(MultipartFile multipart, File destination) throws Exception {
                multipart.transferTo(destination);
                return destination;
            }
        }
        """,
        encoding="utf-8",
    )
    findings = scan(walk_repository(tmp_path).files, ScanConfig(languages=("java",)))
    uploads = [finding for finding in findings if finding.rule_id == "WB.UPLOAD.UNSAFE"]
    assert len(uploads) == 1
    assert uploads[0].verdict_candidate == "informational_inventory"
    assert uploads[0].classification == "review_point"
    assert uploads[0].cwe_ids == []


def test_java_literal_aws_credentials_in_test_source_are_reported(tmp_path: Path):
    target = tmp_path / "src" / "test" / "java"
    target.mkdir(parents=True)
    (target / "TestAmazonS3.java").write_text(
        'class TestAmazonS3 { Object c = new BasicAWSCredentials("AKIA1234567890ABCDEF", "synthetic-secret-key"); }\n',
        encoding="utf-8",
    )
    findings = scan(walk_repository(tmp_path).files, ScanConfig(languages=("java",)))
    aws = [finding for finding in findings if finding.rule_id == "WB.SECRET.HARDCODED"]
    assert len(aws) == 1
    assert aws[0].file_path == "src/test/java/TestAmazonS3.java"
    assert aws[0].suggested_severity == "low"
    assert aws[0].verdict_candidate == "high_confidence_candidate"


def test_go_execution_requires_an_actual_command_invocation(tmp_path: Path):
    (tmp_path / "logging.go").write_text(
        """package main
        import "log"
        func note() { log.Print("exec.Command is not invoked here") }
        // exec.Command("sh", "-c", input)
        """,
        encoding="utf-8",
    )
    (tmp_path / "command.go").write_text(
        """package main
        import "os/exec"
        func run(input string) { exec.Command("sh", "-c", input) }
        """,
        encoding="utf-8",
    )
    findings = scan(walk_repository(tmp_path).files, ScanConfig(languages=("go",)))
    execution = [finding for finding in findings if finding.rule_id == "WB.EXEC.DYNAMIC"]
    assert [(finding.file_path, finding.start_line) for finding in execution] == [("command.go", 3)]


def test_go_sensitive_logging_requires_runtime_sensitive_identifier(tmp_path: Path):
    (tmp_path / "logging.go").write_text(
        """package main
        func missing() { zaplogger.Info("token missing") }
        func leaks(token string) { zaplogger.Info("request", zap.String("token", token)) }
        """,
        encoding="utf-8",
    )
    findings = scan(walk_repository(tmp_path).files, ScanConfig(languages=("go",)))
    logs = [finding for finding in findings if finding.rule_id == "WB.LOG.SENSITIVE_DATA"]
    assert len(logs) == 1
    assert logs[0].start_line == 3
    assert logs[0].cwe_ids == ["CWE-532"]
    assert logs[0].verdict_candidate == "high_confidence_candidate"


def test_javascript_false_positive_regressions_and_true_positives():
    result = walk_repository(FIXTURES / "javascript_pilot")
    findings = scan(result.files, ScanConfig(languages=("javascript", "typescript")))
    by_file = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, set()).add(finding.rule_id)
    assert by_file.get("false_positives.js", set()) == {
        "WB.UPLOAD.CLIENT_CAPABILITY",
        "WB.LOG.SENSITIVE_DATA",
    }
    assert by_file.get("secure.ts", set()) == set()
    assert by_file["vulnerable.js"] >= {
        "WB.UPLOAD.UNSAFE",
        "WB.UPLOAD.ORIGINAL_FILENAME",
        "WB.EXEC.DYNAMIC",
        "WB.SECRET.HARDCODED",
        "WB.SQL.RAW_CONSTRUCTION",
        "WB.SSRF.OUTBOUND_REQUEST",
        "WB.WEB.UNSAFE_RENDER",
    }
    assert all(
        f.invocation_detected
        for f in findings
        if f.rule_id not in {"WB.SECRET.HARDCODED", "WB.WEB.UNSAFE_RENDER"}
    )
    assert all(f.parser_used.startswith("javascript.") for f in findings)
    serialized = json.dumps([f.to_dict() for f in findings])
    assert "actual-long-jwt-secret-value" not in serialized


def test_client_side_formdata_is_a_review_point_not_an_upload_candidate():
    findings = scan(
        walk_repository(FIXTURES / "javascript_pilot").files,
        ScanConfig(languages=("javascript", "typescript")),
    )
    client_uploads = [
        finding for finding in findings if finding.rule_id == "WB.UPLOAD.CLIENT_CAPABILITY"
    ]
    assert len(client_uploads) == 1
    assert client_uploads[0].verdict_candidate == "review_point"
    assert client_uploads[0].cwe_ids == []


def test_javascript_token_presence_logging_is_a_review_point():
    findings = scan(
        walk_repository(FIXTURES / "javascript_pilot").files,
        ScanConfig(languages=("javascript", "typescript")),
    )
    presence_logs = [
        finding
        for finding in findings
        if finding.rule_id == "WB.LOG.SENSITIVE_DATA" and finding.file_path == "false_positives.js"
    ]
    assert len(presence_logs) == 1
    assert presence_logs[0].verdict_candidate == "review_point"
    assert presence_logs[0].cwe_ids == []


def test_java_high_signal_aws_literals_are_detected(tmp_path: Path):
    source = tmp_path / "Credentials.java"
    source.write_text(
        """class Credentials {
        String AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";
        String AWS_SECRET_ACCESS_KEY = "synthetic-secret-key";
        String privateKey = "-----BEGIN PRIVATE KEY-----";
        }""",
        encoding="utf-8",
    )
    findings = scan(walk_repository(tmp_path).files, ScanConfig(languages=("java",)))
    secrets = [finding for finding in findings if finding.rule_id == "WB.SECRET.HARDCODED"]
    assert len(secrets) == 3
    assert all(finding.classification == "high_confidence_candidate" for finding in secrets)
    assert all(finding.cwe_ids == ["CWE-798"] for finding in secrets)


def test_javascript_comment_stripping_preserves_string_literals():
    source = 'const s = "// not a comment"; /* ignored eval(x) */ eval(input);'
    stripped = strip_js_comments(source)
    assert '"// not a comment"' in stripped
    assert "eval(input);" in stripped
