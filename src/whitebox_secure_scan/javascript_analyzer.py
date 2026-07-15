import hashlib
import re

from .config import ScanConfig
from .models import Finding
from .redaction import snippet
from .repository import SourceFile
from .surface import classify_code_surface


def _finding_id(rule: str, path: str, line: int) -> str:
    return hashlib.sha256(f"{rule}:{path}:{line}".encode()).hexdigest()[:16]


def strip_js_comments(source: str) -> str:
    """Strip JS/TS comments while preserving strings, templates, and line numbers."""
    output: list[str] = []
    i = 0
    state = "code"
    template_expr = 0
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char in {'"', "'"}:
                state = char
                output.append(char)
            elif char == "`":
                state = "template"
                output.append(char)
            elif char == "/" and next_char == "/":
                state = "line_comment"
                output.extend("  ")
                i += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.extend("  ")
                i += 1
            else:
                output.append(char)
        elif state == "line_comment":
            if char == "\n":
                state = "code"
                output.append(char)
            else:
                output.append(" ")
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend("  ")
                i += 1
                state = "code"
            elif char == "\n":
                output.append("\n")
            else:
                output.append(" ")
        elif state == "template":
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                i += 1
            elif char == "`":
                state = "code"
            elif char == "$" and next_char == "{":
                template_expr += 1
        else:
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                i += 1
            elif char == "}" and template_expr:
                template_expr -= 1
            elif template_expr == 0 and char == "`":
                state = "code"
        i += 1
    return "".join(output)


def _mask_strings(source: str) -> str:
    output: list[str] = []
    state = "code"
    i = 0
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code" and char in {'"', "'", "`"}:
            state = char
            output.append(" ")
        elif state in {'"', "'", "`"}:
            output.append("\n" if char == "\n" else " ")
            if char == "\\" and next_char:
                output.append(" ")
                i += 1
            elif char == state:
                state = "code"
        else:
            output.append(char)
        i += 1
    return "".join(output)


def _surface(file: SourceFile) -> str:
    return file.code_surface if file.code_surface != "unknown" else classify_code_surface(file.path)


def _make(
    rule: str,
    title: str,
    file: SourceFile,
    line: int,
    config: ScanConfig,
    *,
    severity: str,
    confidence: int,
    syntax: str,
    api: str,
    source: str | None = None,
    sink: str | None = None,
    controls: list[str] | None = None,
    cwes: list[str] | None = None,
    verdict: str = "secure_coding_concern",
    classification: str = "review_lead",
    reason: str,
    proof_gaps: list[str] | None = None,
    counterevidence: list[str] | None = None,
    sensitive_value: str | None = None,
) -> Finding:
    surface = _surface(file)
    return Finding(
        id=_finding_id(rule, str(file.path), line),
        rule_id=rule,
        title=title,
        description=reason,
        category={
            "WB.UPLOAD.UNSAFE": "file_upload",
            "WB.UPLOAD.ORIGINAL_FILENAME": "file_upload",
            "WB.UPLOAD.CLIENT_CAPABILITY": "file_upload",
            "WB.LOG.SENSITIVE_DATA": "logging",
            "WB.EXEC.DYNAMIC": "command_execution",
            "WB.SECRET.HARDCODED": "secrets",
            "WB.SQL.RAW_CONSTRUCTION": "sql",
            "WB.SSRF.OUTBOUND_REQUEST": "ssrf",
            "WB.WEB.UNSAFE_RENDER": "web",
        }.get(rule, "secure-coding"),
        subcategory="javascript-aware",
        language=file.language,
        framework=None,
        classification=classification,
        confidence_score=confidence,
        suggested_severity=severity,
        cwe_ids=cwes or [],
        file_path=str(file.path),
        start_line=line,
        end_line=line,
        source=source,
        sink=sink,
        data_flow=[f"syntax={syntax}", f"invoked_api={api}"],
        observed_controls=controls or [],
        missing_or_questionable_controls=["Validate the complete source-to-sink flow."],
        proof_gaps=proof_gaps or [],
        counterevidence=counterevidence or [],
        evidence=snippet(
            file.text.splitlines(), line, config.snippets, config.max_snippet_lines, config.redact
        ),
        false_positive_conditions=["The call may be protected by controls outside this file."],
        recommended_verification_steps=[
            reason,
            "Trace the source and verify runtime behavior before confirming.",
        ],
        recommended_remediation="Use a safe API, allowlist, validation, or framework control appropriate to the sink.",
        analyzer="javascript.ast-aware-lexical",
        verdict_candidate=verdict,
        code_surface=surface,
        test_surface=surface == "test",
        reachability="test_only" if surface == "test" else "unknown",
        parser_used="javascript.structured-lexical",
        syntax_node_type=syntax,
        invocation_detected=syntax in {"call_expression", "constructor_invocation"},
        exact_invoked_api=api,
        sensitive_value=sensitive_value,
        verification_notes=f"syntax={syntax}; invoked_api={api}; source={source or 'unknown'}; sink={sink or 'unknown'}; controls={controls or []}; reason={reason}",
    )


def _controls(text: str) -> list[str]:
    checks = (
        ("size limit", "size"),
        ("MIME validation", "mimetype"),
        ("extension allowlist", "extension"),
        ("content sniffing", "magic"),
        ("random object key", "uuid"),
        ("path normalization", "normalize"),
        ("sanitization", "dompurify"),
        ("parameter binding", "parameter"),
    )
    return [name for name, marker in checks if marker in text.lower()]


def analyze_javascript(file: SourceFile, config: ScanConfig) -> list[Finding]:
    uncommented = strip_js_comments(file.text)
    code = _mask_strings(uncommented)
    lines = code.splitlines()
    original_lines = file.text.splitlines()
    findings: list[Finding] = []
    aliases: set[str] = set()
    for line in lines:
        if re.search(
            r"(?:require\s*\(\s*['\"](?:node:)?child_process|from\s+['\"](?:node:)?child_process)",
            line,
        ):
            aliases.update(
                re.findall(
                    r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\b", line
                )
            )

    def add(*args, **kwargs):
        findings.append(_make(*args, **kwargs))

    aws = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
    secret_assignment = re.compile(
        r"(?i)\b(?:jwt[_-]?secret|api[_-]?key|client[_-]?secret|password|token)\s*[:=]\s*(['\"])([^'\"]{12,})\1"
    )
    credential_constructor = re.compile(
        r"new\s+\w*(?:Credential|Token|Auth)\s*\(\s*['\"][^'\"]{6,}['\"]"
    )
    for line_no, line in enumerate(lines, 1):
        original = original_lines[line_no - 1] if line_no <= len(original_lines) else line
        window = "\n".join(lines[max(0, line_no - 2) : line_no + 2])
        original_window = "\n".join(original_lines[max(0, line_no - 2) : line_no + 2])

        secret_match = secret_assignment.search(original)
        if aws.search(original) or secret_match or credential_constructor.search(original):
            literal_reason = "A literal credential-like value matches a known secret shape or credential context."
            if secret_match and re.search(
                r"(?i)process\.env|import\.meta\.env|secretmanager|vault", original
            ):
                literal_reason = "Environment or secret-manager lookup is not a literal secret."
            elif not re.search(
                r"(?i)(process\.env|import\.meta\.env|secretmanager|vault)", original
            ):
                add(
                    "WB.SECRET.HARDCODED",
                    "Hardcoded JavaScript/TypeScript secret candidate",
                    file,
                    line_no,
                    config,
                    severity="high",
                    confidence=90,
                    syntax="literal_assignment" if secret_match else "credential_constructor",
                    api="literal credential",
                    source="literal value",
                    sink="authentication or credential configuration",
                    cwes=["CWE-798"],
                    verdict="confirmed",
                    classification="high_confidence_candidate",
                    sensitive_value="credential literal (redacted)",
                    reason=literal_reason,
                    proof_gaps=[
                        "Rotation and repository-history exposure require operational verification."
                    ],
                )

        logging = re.search(
            r"(?i)\b(?:console\.(?:log|error|warn|info)|(?:logger|log)\.(?:debug|info|warn|error))\s*\(",
            line,
        )
        if logging and re.search(
            r"(?i)\b(?:token|access[_-]?token|refresh[_-]?token|authorization|bearer|jwt|password|secret|api[_-]?key|apiKey|cookie|session[_-]?id|sessionId)\b",
            line,
        ):
            presence_only = bool(
                re.search(
                    r"(?i)\b(?:access[_-]?token|refresh[_-]?token|token|authorization|jwt)\b\s*\?\s*['\"]"
                    r"(?:exists|present|available|set|true)['\"]\s*:\s*['\"]"
                    r"(?:undefined|missing|absent|false|not[ _-]?set)['\"]",
                    original,
                )
            )
            add(
                "WB.LOG.SENSITIVE_DATA",
                "Sensitive token presence logged"
                if presence_only
                else "Sensitive value passed to a JavaScript logging sink",
                file,
                line_no,
                config,
                severity="informational" if presence_only else "medium",
                confidence=28 if presence_only else 84,
                syntax="call_expression",
                api="logger/console logging",
                source="token-presence boolean"
                if presence_only
                else "sensitive runtime identifier",
                sink="logging method",
                cwes=[] if presence_only else ["CWE-532"],
                verdict="review_point" if presence_only else "high_confidence_candidate",
                classification="review_point" if presence_only else "high_confidence_candidate",
                reason=(
                    "A logging call exposes only whether a token exists; the token value itself is not observed."
                    if presence_only
                    else "A sensitive runtime identifier appears in actual logging-call arguments."
                ),
                counterevidence=["Ternary status logging avoids the token value."]
                if presence_only
                else [],
            )

        exec_api = None
        if re.search(r"\beval\s*\(", line):
            exec_api = "eval"
        elif re.search(r"\b(?:new\s+)?Function\s*\(", line):
            exec_api = "Function"
        else:
            process_call = re.search(
                r"\bchild_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(",
                line,
            )
            if process_call:
                exec_api = process_call.group(0).strip(" (")
        if exec_api is None and any(
            re.search(rf"\b{re.escape(alias)}\s*\(", line) for alias in aliases
        ):
            exec_api = next(
                alias for alias in aliases if re.search(rf"\b{re.escape(alias)}\s*\(", line)
            )
        if exec_api is None:
            vm_call = re.search(
                r"\bvm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(",
                line,
            )
            if vm_call:
                vm_api = re.search(r"\bvm\.[A-Za-z]+", line)
                exec_api = vm_api.group(0) if vm_api else "vm"
        if exec_api:
            controlled = bool(
                re.search(r"(?i)(req\.|request\.|body|query|params|input|user|payload)", original)
            )
            add(
                "WB.EXEC.DYNAMIC",
                "Dynamic JavaScript execution candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=90 if controlled else 66,
                syntax="call_expression",
                api=exec_api,
                source="request-controlled input" if controlled else "unknown",
                sink=exec_api,
                cwes=["CWE-95" if exec_api in {"eval", "Function"} else "CWE-78"],
                verdict="high_confidence_candidate" if controlled else "secure_coding_concern",
                classification="high_confidence_candidate" if controlled else "review_lead",
                reason=f"Actual invocation of {exec_api} detected; argument provenance requires verification.",
            )

        upload_source = re.search(
            r"(?i)(req\.(?:file|files)|request\.(?:file|files)|multer|busboy|formidable|UploadedFile|UploadedFiles|FormData)",
            window,
        )
        upload_sink = re.search(
            r"(?i)(fs\.(?:writeFile|writeFileSync|createWriteStream)|stream\.pipeline|putObject\s*\(|\.upload\s*\(|\.put\s*\()",
            line,
        )
        client_upload = re.search(
            r"(?i)\b\w*formdata\s*\.\s*append\s*\([^,]+,\s*(?:file|image\w*|buffer|stream)\b",
            line,
        )
        if client_upload and not upload_sink:
            add(
                "WB.UPLOAD.CLIENT_CAPABILITY",
                "Client-side multipart construction requires server-side context",
                file,
                line_no,
                config,
                severity="informational",
                confidence=25,
                syntax="call_expression",
                api="FormData.append",
                source="browser-selected file or image",
                sink="outbound multipart request (server storage not observed)",
                cwes=[],
                verdict="review_point",
                classification="review_point",
                reason="Client-side multipart construction alone does not establish backend storage, missing validation, or file-upload exploitability.",
                proof_gaps=[
                    "No backend endpoint, storage sink, validation behavior, or serving configuration is visible."
                ],
                counterevidence=["Only frontend multipart request construction is observable."],
            )
        if upload_source and upload_sink:
            add(
                "WB.UPLOAD.UNSAFE",
                "JavaScript/TypeScript uploaded-file flow requires validation review",
                file,
                line_no,
                config,
                severity="medium",
                confidence=68,
                syntax="call_expression",
                api=upload_sink.group(0).strip(" ("),
                source=upload_source.group(0),
                sink="file or remote storage upload",
                controls=_controls(original_window),
                cwes=["CWE-434"],
                verdict="secure_coding_concern",
                reason="An uploaded-file source and an actual write/storage sink are both observable.",
                proof_gaps=[
                    "Serving behavior and storage ACL are not visible.",
                    "Malware scanning and content transformation may be implemented elsewhere.",
                ],
            )
            if re.search(r"(?i)(originalname|filename)", original_window) and re.search(
                r"(?i)(writeFile|putObject|upload|createWriteStream)", original_window
            ):
                add(
                    "WB.UPLOAD.ORIGINAL_FILENAME",
                    "Original filename reaches a JavaScript/TypeScript storage sink",
                    file,
                    line_no,
                    config,
                    severity="high",
                    confidence=78,
                    syntax="call_expression",
                    api="filename plus upload/storage API",
                    source="uploaded file metadata",
                    sink="file/object storage",
                    controls=_controls(original_window),
                    cwes=["CWE-22", "CWE-434"],
                    verdict="runtime_verification_required",
                    reason="Client-provided filename appears in a real upload/storage flow.",
                )

        sql_sink = re.search(
            r"(?i)(?:sequelize|knex|prisma|connection|db|pool)\.(?:query|raw|execute)\s*\(", line
        )
        if (
            sql_sink
            and re.search(r"(?i)(select|insert|update|delete)", original)
            and re.search(r"\+|\$\{|String\.raw", original)
        ):
            safe_bind = bool(
                re.search(r"\?|\$[0-9]+|parameters|replacements|\$queryRaw`", original, re.I)
            )
            if not safe_bind:
                add(
                    "WB.SQL.RAW_CONSTRUCTION",
                    "Dynamic SQL reaches a JavaScript/TypeScript execution API",
                    file,
                    line_no,
                    config,
                    severity="high",
                    confidence=86,
                    syntax="call_expression",
                    api=sql_sink.group(0).strip(" ("),
                    source="request-controlled input"
                    if re.search(r"req\.|request\.|query|body|params", original, re.I)
                    else "unknown",
                    sink="SQL execution",
                    cwes=["CWE-89"],
                    verdict="high_confidence_candidate",
                    classification="high_confidence_candidate",
                    reason="Dynamic SQL construction is adjacent to an observable query execution call.",
                )

        outbound = re.search(
            r"(?i)\b(?:fetch|axios\.(?:get|post|request)|got|request|http\.request)\s*\(", line
        )
        if outbound and re.search(
            r"(?i)(req\.|request\.|query|body|params|user|payload)", original
        ):
            add(
                "WB.SSRF.OUTBOUND_REQUEST",
                "User-controlled URL reaches an outbound request API",
                file,
                line_no,
                config,
                severity="medium",
                confidence=70,
                syntax="call_expression",
                api=outbound.group(0).strip(" ("),
                source="request-derived URL",
                sink="outbound HTTP request",
                cwes=["CWE-918"],
                reason="An outbound request invocation uses a potentially request-derived URL.",
            )

        xss = re.search(
            r"(?i)(innerHTML\s*=|outerHTML\s*=|dangerouslySetInnerHTML|v-html|document\.write\s*\()",
            line,
        )
        if xss and not re.search(r"(?i)(dompurify|sanitize)", window):
            add(
                "WB.WEB.UNSAFE_RENDER",
                "Unsafe JavaScript/TypeScript HTML rendering candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=72,
                syntax="assignment_or_call",
                api=xss.group(0).strip(" =("),
                source="user-controlled value if propagated",
                sink="HTML rendering",
                cwes=["CWE-79"],
                reason="An executable HTML rendering sink is present without an observable sanitizer.",
            )

    return findings
