import ast
import hashlib
import re
from .config import ScanConfig
from .java_analyzer import analyze_java
from .javascript_analyzer import analyze_javascript
from .models import Finding
from .parsers import parse
from .redaction import snippet
from .repository import SourceFile
from .surface import classify_code_surface


def _id(rule: str, path: str, line: int) -> str:
    return hashlib.sha256(f"{rule}:{path}:{line}".encode()).hexdigest()[:16]


def _make(
    rule: str,
    title: str,
    category: str,
    file: SourceFile,
    line: int,
    evidence: str,
    config: ScanConfig,
    **kw,
) -> Finding:
    confidence = int(kw.pop("confidence_score", 65))
    classification = kw.pop(
        "classification", "high_confidence_candidate" if confidence >= 75 else "review_lead"
    )
    severity = kw.pop("severity", "medium")
    surface = (
        file.code_surface if file.code_surface != "unknown" else classify_code_surface(file.path)
    )
    verdict = kw.pop(
        "verdict_candidate",
        "high_confidence_candidate" if confidence >= 75 else "secure_coding_concern",
    )
    return Finding(
        id=_id(rule, str(file.path), line),
        rule_id=rule,
        title=title,
        description=kw.pop("description", title),
        category=category,
        subcategory=kw.pop("subcategory", "secure-coding"),
        language=file.language,
        classification=classification,
        confidence_score=confidence,
        suggested_severity=severity,
        verdict_candidate=verdict,
        code_surface=surface,
        test_surface=surface == "test",
        parser_used="python.ast" if file.language == "python" else "lexical",
        file_path=str(file.path),
        start_line=line,
        end_line=line,
        evidence=snippet(
            file.text.splitlines(), line, config.snippets, config.max_snippet_lines, config.redact
        ),
        **kw,
    )


PATTERNS = [
    (
        "WB.SECRET.HARDCODED",
        r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "Hardcoded credential or secret candidate",
        "secrets",
        "high",
        86,
        ["CWE-798"],
    ),
    (
        "WB.CRYPTO.TLS_VERIFY_DISABLED",
        r"(?i)(verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|TrustAll|NoopHostnameVerifier)",
        "TLS certificate or hostname verification disabled",
        "cryptography",
        "high",
        90,
        ["CWE-295"],
    ),
    (
        "WB.CRYPTO.WEAK_PRIMITIVE",
        r"(?i)\b(md5|sha1|des|3des|rc4|ecb|java\.util\.Random|math/rand|Math\.random)\b",
        "Weak cryptographic primitive or randomness candidate",
        "cryptography",
        "medium",
        62,
        ["CWE-327"],
    ),
    (
        "WB.EXEC.DYNAMIC",
        r"(?i)(eval\s*\(|exec\s*\(|compile\s*\(|Function\s*\(|vm\.run|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os\.system\s*\(|subprocess\.(run|Popen|call)|child_process|exec\.Command)",
        "Dynamic or operating-system command execution",
        "command_execution",
        "high",
        82,
        ["CWE-78"],
    ),
    (
        "WB.DESERIALIZATION.UNSAFE",
        r"(?i)(yaml\.load\s*\(|pickle\.loads?\s*\(|marshal\.loads?\s*\(|ObjectInputStream|gob\.NewDecoder|JSON\.parse\s*\([^)]*user)",
        "Unsafe deserialization or parser configuration candidate",
        "deserialization",
        "high",
        80,
        ["CWE-502"],
    ),
    (
        "WB.SQL.RAW_CONSTRUCTION",
        r"(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|f['\"]|fmt\.Sprintf|literal|Sprintf)",
        "SQL constructed dynamically",
        "sql",
        "high",
        80,
        ["CWE-89"],
    ),
    (
        "WB.SSRF.OUTBOUND_REQUEST",
        r"(?i)(http\.get\s*\(|requests\.(get|post)\s*\(|httpx\.(get|post)\s*\(|axios\.(get|post)\s*\(|fetch\s*\(|client\.do\s*\(|http\.NewRequest)",
        "Outbound request requires SSRF review",
        "ssrf",
        "medium",
        55,
        ["CWE-918"],
    ),
    (
        "WB.WEB.UNSAFE_RENDER",
        r"(?i)(innerHTML\s*=|dangerouslySetInnerHTML|document\.write|mark_safe\s*\(|template\.HTML\s*\(|text/template|res\.redirect\s*\(\s*(req|request)|sendRedirect)",
        "Unsafe HTML rendering, template, or redirect candidate",
        "web",
        "high",
        70,
        ["CWE-79", "CWE-601"],
    ),
    (
        "WB.FILE.PATH_INPUT",
        r"(?i)(send_file|send_from_directory|filepath\.Join|path\.join|open\s*\(|readFile|writeFile|os\.Remove|zip\.extract|tarfile)",
        "User-controlled path or archive operation requires traversal review",
        "file_handling",
        "high",
        58,
        ["CWE-22"],
    ),
    (
        "WB.AUTHZ.CONTROL_WEAK",
        r"(?i)(csrf_exempt|permitAll\s*\(|cors\s*\(.*\*|Access-Control-Allow-Origin.*\*|trust proxy|AllowAll|@PermitAll)",
        "Authentication, CSRF, CORS, or authorization control may be overly permissive",
        "authorization",
        "medium",
        60,
        ["CWE-352", "CWE-862", "CWE-942"],
    ),
    (
        "WB.UPLOAD.UNSAFE",
        r"(?i)(multer|FileUpload|MultipartFile|UploadFile|filename|originalname)",
        "File upload handling requires validation and storage review",
        "file_upload",
        "medium",
        52,
        ["CWE-434"],
    ),
    (
        "WB.LOG.SENSITIVE_DATA",
        r"(?i)\b(?:log|logger|systemLogger|zaplogger|zap)\s*\.|\bfmt\.(?:Print|Printf|Println)\s*\(",
        "Sensitive runtime value may be written to logs",
        "logging",
        "high",
        78,
        ["CWE-532"],
    ),
    (
        "WB.CONFIG.DEBUG",
        r"(?i)(DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)",
        "Debug or development mode enabled",
        "configuration",
        "medium",
        76,
        ["CWE-489"],
    ),
    (
        "WB.JWT.DECODE_UNVERIFIED",
        r"(?i)(jwt\.decode\s*\(|jsonwebtoken\.decode\s*\()",
        "JWT decoding requires signature and claim validation review",
        "authentication",
        "high",
        72,
        ["CWE-347"],
    ),
    (
        "WB.RANDOM.PREDICTABLE",
        r"(?i)(random\.random\s*\(|Math\.random\s*\(|math/rand|java\.util\.Random)",
        "Predictable randomness used in a security-sensitive context",
        "cryptography",
        "medium",
        68,
        ["CWE-330"],
    ),
    (
        "WB.XML.UNSAFE",
        r"(?i)(DocumentBuilderFactory|SAXParserFactory|xml\.etree|lxml\.etree|XMLDecoder|SAXParser)",
        "XML parser configuration requires XXE review",
        "deserialization",
        "high",
        55,
        ["CWE-611"],
    ),
    (
        "WB.DOS.TIMEOUT",
        r"(?i)(requests\.(get|post)|httpx\.(get|post)|axios\.(get|post)|http\.Get\s*\(|client\.Do\s*\()",
        "Outbound HTTP call requires an explicit timeout review",
        "denial_of_service",
        "low",
        48,
        ["CWE-400"],
    ),
]


def _mask_go_comments_and_literals(source: str) -> str:
    """Keep Go call syntax while removing comments and literal contents."""
    output: list[str] = []
    state = "code"
    i = 0
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                output.extend("  ")
                i += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.extend("  ")
                i += 1
            elif char in {'"', "'", "`"}:
                state = {'"': "string", "'": "char", "`": "raw_string"}[char]
                output.append(" ")
            else:
                output.append(char)
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend("  ")
                i += 1
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
        else:
            output.append("\n" if char == "\n" else " ")
            if char == "\\" and state != "raw_string" and next_char:
                output.append(" ")
                i += 1
            elif (
                (state == "string" and char == '"')
                or (state == "char" and char == "'")
                or (state == "raw_string" and char == "`")
            ):
                state = "code"
        i += 1
    return "".join(output)


def _python_controls(text: str, node: ast.AST) -> list[str]:
    segment = ast.get_source_segment(text, node) or ""
    return [
        x
        for x, marker in (
            ("validation", "validate"),
            ("ownership check", "owner"),
            ("tenant check", "tenant"),
            ("role check", "role"),
            ("parameter binding", "param"),
        )
        if marker in segment.lower()
    ]


_LOGGING_SINK = re.compile(
    r"(?i)(?:\b(?:log|logger|systemLogger|accessLogger|auditLogger|zaplogger)\s*\.\s*"
    r"(?:debug|info|warn|error|fatal|print)\s*\(|\bzap\.(?:String|Any|ByteString)\s*\(|"
    r"\bfmt\.(?:Print|Printf|Println)\s*\()"
)
_SENSITIVE_IDENTIFIER = re.compile(
    r"(?i)\b(?:token|access[_-]?token|refresh[_-]?token|authorization|bearer|jwt|"
    r"api[_-]?key|apikey|password|secret|client[_-]?secret|cookie|session[_-]?id)\b"
)


def analyze_file(
    file: SourceFile, config: ScanConfig, framework: str | None = None
) -> list[Finding]:
    if file.language == "java":
        return analyze_java(file, config)
    if file.language in {"javascript", "typescript"}:
        return analyze_javascript(file, config)
    findings: list[Finding] = []
    lines = file.text.splitlines()
    go_code_lines = (
        _mask_go_comments_and_literals(file.text).splitlines() if file.language == "go" else lines
    )
    literal_free_lines = (
        _mask_go_comments_and_literals(file.text).splitlines()
        if file.language in {"go", "python"}
        else lines
    )
    for i, line in enumerate(lines, 1):
        for rule, pattern, title, category, severity, confidence, cwes in PATTERNS:
            if rule == "WB.EXEC.DYNAMIC" and file.language == "go":
                code_line = go_code_lines[i - 1] if i <= len(go_code_lines) else ""
                if not re.search(
                    r"\b(?:exec\.(?:Command|CommandContext)|syscall\.Exec)\s*\(",
                    code_line,
                ):
                    continue
            if rule == "WB.LOG.SENSITIVE_DATA":
                code_line = literal_free_lines[i - 1] if i <= len(literal_free_lines) else ""
                if not (
                    _LOGGING_SINK.search(code_line) and _SENSITIVE_IDENTIFIER.search(code_line)
                ):
                    continue
            if re.search(pattern, line):
                if rule == "WB.EXEC.DYNAMIC" and (
                    "shell=False" in line or re.search(r"new\s+ProcessBuilder\s*\(\s*[\"']", line)
                ):
                    continue
                if rule == "WB.DOS.TIMEOUT" and re.search(r"(?i)(timeout\s*=|timeout:)", line):
                    continue
                kw = {
                    "severity": severity,
                    "confidence_score": confidence,
                    "framework": framework,
                    "cwe_ids": cwes,
                    "analyzer": f"{file.language}.lexical",
                }
                if rule in {
                    "WB.SQL.RAW_CONSTRUCTION",
                    "WB.EXEC.DYNAMIC",
                    "WB.SSRF.OUTBOUND_REQUEST",
                }:
                    kw.update(
                        source="request-derived input if propagated",
                        sink=category,
                        data_flow=[
                            "partial source-to-sink evidence; interprocedural flow not proven"
                        ],
                    )
                if rule in {"WB.AUTHZ.CONTROL_WEAK", "WB.FILE.PATH_INPUT", "WB.UPLOAD.UNSAFE"}:
                    kw.update(
                        classification="review_lead",
                        recommended_verification_steps=[
                            "Trace the complete handler and surrounding controls before confirming."
                        ],
                    )
                if rule == "WB.CRYPTO.WEAK_PRIMITIVE":
                    kw.update(
                        classification="review_lead",
                        false_positive_conditions=["Non-security checksum or test-only use."],
                    )
                if rule == "WB.RANDOM.PREDICTABLE":
                    security_context = bool(
                        re.search(
                            r"(?i)(otp|token|session|password|reset|auth(?:entication)?|secret)",
                            line,
                        )
                    )
                    if not security_context:
                        kw.update(
                            severity="informational",
                            confidence_score=30,
                            classification="review_point",
                            verdict_candidate="review_point",
                            cwe_ids=[],
                            false_positive_conditions=[
                                "Randomness is not shown to generate a security-sensitive value."
                            ],
                        )
                if rule == "WB.LOG.SENSITIVE_DATA":
                    kw.update(
                        severity="medium",
                        confidence_score=84,
                        classification="high_confidence_candidate",
                        verdict_candidate="high_confidence_candidate",
                        source="sensitive runtime identifier",
                        sink="logging method",
                        data_flow=["sensitive identifier reaches an observable logging sink"],
                        logging_sink="logger/log/zap/fmt",
                        sensitive_value="sensitive runtime identifier (redacted)",
                    )
                findings.append(_make(rule, title, category, file, i, line, config, **kw))
    parsed = parse(file)
    if parsed.error:
        return findings
    if file.language == "python" and parsed.tree:
        for node in ast.walk(parsed.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and re.search(
                r"(?i)(delete|update|admin|transfer|password|login)", node.name
            ):
                controls = _python_controls(file.text, node)
                if not controls:
                    findings.append(
                        _make(
                            "WB.AUTHZ.MISSING_OBSERVABLE_CONTROL",
                            "Sensitive function lacks an observable authorization control",
                            "authorization",
                            file,
                            node.lineno,
                            node.name,
                            config,
                            confidence_score=45,
                            classification="review_lead",
                            severity="medium",
                            function=node.name,
                            missing_or_questionable_controls=[
                                "No authorization control observed in the function"
                            ],
                            recommended_verification_steps=[
                                "Trace middleware, decorators, and service-layer checks before confirming."
                            ],
                            recommended_remediation="Enforce authorization at the server boundary and in the service layer.",
                            analyzer="python.ast",
                        )
                    )
    return findings


def scan(
    files: list[SourceFile], config: ScanConfig, framework: str | None = None
) -> list[Finding]:
    unique: dict[tuple[str, str, int], Finding] = {}
    for file in files:
        if config.languages and file.language not in config.languages:
            continue
        parsed = parse(file)
        for finding in analyze_file(file, config, framework):
            if parsed.parser_used not in {"none", "lexical-fallback"}:
                finding.parser_used = parsed.parser_used
                finding.syntax_node_type = parsed.syntax_node_type
            finding.rule_family = (
                finding.rule_id.split(".")[1] if "." in finding.rule_id else finding.rule_id
            )
            finding.test_only = finding.code_surface == "test"
            finding.production_reachability = "production" if not finding.test_only else "test_only"
            finding.source_detected = bool(finding.source)
            finding.sink_detected = bool(finding.sink)
            if finding.source_detected and finding.sink_detected and finding.invocation_detected:
                finding.flow_status = "partial"
                finding.evidence_level = 2
            elif finding.sink_detected or finding.invocation_detected:
                finding.flow_status = "sink_only"
                finding.evidence_level = 0
                if finding.classification == "review_lead":
                    finding.verdict_candidate = "review_point"
                    finding.classification = "review_point"
                    finding.suggested_severity = "informational"
                    finding.cwe_ids = []
            finding.evidence_score = min(100, finding.confidence_score)
            finding.evidence_completeness = {
                "source_identified": finding.source_detected,
                "sink_identified": finding.sink_detected,
                "actual_invocation_confirmed": finding.invocation_detected,
                "production_surface": not finding.test_only,
                "runtime_dependency_remaining": bool(finding.proof_gaps),
            }
            if config.production_only and finding.test_only:
                if not (config.include_test_secrets and finding.rule_id == "WB.SECRET.HARDCODED"):
                    continue
            if (
                finding.test_only
                and not config.include_test_code
                and not config.include_test_review_points
                and finding.rule_id != "WB.SECRET.HARDCODED"
            ):
                continue
            if config.result_types and finding.verdict_candidate not in config.result_types:
                continue
            if finding.evidence_level < config.minimum_evidence_level:
                continue
            if config.severities and finding.suggested_severity not in config.severities:
                continue
            if finding.confidence_score < config.min_confidence:
                continue
            unique[(finding.rule_id, finding.file_path, finding.start_line)] = finding
    return list(unique.values())
