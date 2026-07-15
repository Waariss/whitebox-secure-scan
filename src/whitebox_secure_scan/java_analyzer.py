import hashlib
import re

from .config import ScanConfig
from .models import Finding
from .redaction import snippet
from .repository import SourceFile
from .surface import classify_code_surface


def _finding_id(rule: str, path: str, line: int) -> str:
    return hashlib.sha256(f"{rule}:{path}:{line}".encode()).hexdigest()[:16]


def strip_java_comments(source: str) -> str:
    """Remove Java comments while preserving newlines and quoted literals."""
    output: list[str] = []
    i = 0
    state = "code"
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == '"':
                state = "string"
                output.append(char)
            elif char == "'":
                state = "char"
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
        else:
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                i += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
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
        if state == "code" and char in {'"', "'"}:
            state = "string" if char == '"' else "char"
            output.append(" ")
        elif state in {"string", "char"}:
            output.append("\n" if char == "\n" else " ")
            if char == "\\" and next_char:
                output.append(" ")
                i += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        else:
            output.append(char)
        i += 1
    return "".join(output)


def _has_hardcoded_secret_assignment(source: str) -> bool:
    """Return true only for a credential literal assigned in Java code.

    This deliberately scans Java lexical states instead of applying a regular
    expression to the whole line.  In particular, ``logger.info(\"token=\" +
    token)`` contains text that resembles an assignment but is not one.
    Comments have already been removed by the caller.
    """
    assignment = re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token|clientsecret)\b\s*=\s*\"")
    i = 0
    state = "code"
    while i < len(source):
        char = source[i]
        if state == "code":
            if char == '"':
                state = "string"
                i += 1
                continue
            if char == "'":
                state = "char"
                i += 1
                continue
            match = assignment.match(source, i)
            if match:
                value_start = match.end()
                cursor = value_start
                escaped = False
                while cursor < len(source):
                    current = source[cursor]
                    if current == '"' and not escaped:
                        break
                    if current == "\\" and not escaped:
                        escaped = True
                    else:
                        escaped = False
                    cursor += 1
                if cursor < len(source):
                    value = source[value_start:cursor]
                    suffix = source[cursor + 1 :].lstrip()
                    if len(value) >= 8 and (not suffix or suffix[0] in ";,)"):
                        return True
                i = max(cursor + 1, i + 1)
                continue
        elif char == "\\" and i + 1 < len(source):
            i += 2
            continue
        elif (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
        i += 1
    return False


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
    classification: str = "review_lead",
    verdict_candidate: str = "secure_coding_concern",
    reason: str = "Java invocation matched a security-sensitive sink.",
    proof_gaps: list[str] | None = None,
    counterevidence: list[str] | None = None,
    sensitive_value: str | None = None,
    logging_sink: str | None = None,
    masking_detected: bool = False,
) -> Finding:
    surface = (
        file.code_surface if file.code_surface != "unknown" else classify_code_surface(file.path)
    )
    return Finding(
        id=_finding_id(rule, str(file.path), line),
        rule_id=rule,
        title=title,
        description=reason,
        category={
            "WB.UPLOAD.UNSAFE": "file_upload",
            "WB.SQL.RAW_CONSTRUCTION": "sql",
            "WB.EXEC.DYNAMIC": "command_execution",
            "WB.FILE.PATH_INPUT": "file_handling",
            "WB.DESERIALIZATION.UNSAFE": "deserialization",
            "WB.CRYPTO.TLS_VERIFY_DISABLED": "cryptography",
            "WB.SECRET.HARDCODED": "secrets",
            "WB.RANDOM.PREDICTABLE": "cryptography",
            "WB.LOG.SENSITIVE_DATA": "logging",
        }.get(rule, "secure-coding"),
        subcategory="java-aware",
        language="java",
        framework=None,
        classification=classification,
        verdict_candidate=verdict_candidate,
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
        proof_gaps=proof_gaps or [],
        counterevidence=counterevidence or [],
        parser_used="java.structured-lexical",
        syntax_node_type=syntax,
        invocation_detected=syntax in {"method_invocation", "constructor_invocation"},
        declaration_detected=False,
        comment_context="active_code",
        code_surface=surface,
        test_surface=surface == "test",
        reachability="test_only" if surface == "test" else "unknown",
        exact_invoked_api=api,
        sensitive_value=sensitive_value,
        logging_sink=logging_sink,
        masking_detected=masking_detected,
        redaction_detected=masking_detected,
        missing_controls=["Input validation or sink control requires review."],
        missing_or_questionable_controls=["Input validation or sink control requires review."],
        evidence=snippet(
            file.text.splitlines(), line, config.snippets, config.max_snippet_lines, config.redact
        ),
        false_positive_conditions=[
            "The call may be unreachable or protected by controls outside this file."
        ],
        recommended_verification_steps=[
            reason,
            "Trace the caller and verify whether attacker-controlled data reaches the sink.",
        ],
        recommended_remediation="Use a safe, parameterized API and enforce validation or allowlists at the sink.",
        analyzer="java.ast-aware-lexical",
        verification_notes=f"syntax={syntax}; invoked_api={api}; source={source or 'unknown'}; sink={sink or 'unknown'}; controls={controls or []}; reason={reason}",
    )


def _has_control(text: str) -> list[str]:
    controls: list[str] = []
    checks = (
        ("normalization", "normalize("),
        ("canonicalization", "getCanonical"),
        ("real path", "toRealPath"),
        ("allowlist", "startsWith("),
        ("parameter binding", ".setString("),
        ("validation", "validate"),
        ("size limit", "getSize"),
        ("content type validation", "contentType"),
        ("MIME validation", "mime"),
        ("extension allowlist", "extension"),
        ("magic-byte validation", "magic"),
        ("malware scanning", "clamav"),
        ("virus scanning", "virusScan"),
    )
    for name, marker in checks:
        if marker.lower() in text.lower():
            controls.append(name)
    return controls


def _upload_source_context(lines: list[str], line_no: int) -> str:
    """Return the nearby method context used to prove an uploaded-file source.

    A file-write API alone is common in batch exports and report generation.
    This bounded context intentionally looks for an HTTP multipart/file source
    close to the storage call rather than treating variable names or output
    APIs as upload evidence.
    """
    start = max(0, line_no - 20)
    end = min(len(lines), line_no + 3)
    return "\n".join(lines[start:end])


def _has_uploaded_file_source(context: str) -> bool:
    return bool(
        re.search(
            r"(?i)(?:\bMultipartFile\b|\bPart\b|@RequestPart\b|"
            r"@RequestParam\s*\([^)]*(?:file|upload)|"
            r"(?:request|httpServletRequest)\s*\.\s*getPart(?:s)?\s*\(|"
            r"getOriginalFilename\s*\(|(?:request|req)\s*\.\s*(?:file|files)\b)",
            context,
        )
    )


def analyze_java(file: SourceFile, config: ScanConfig) -> list[Finding]:
    uncommented = strip_java_comments(file.text)
    code = _mask_strings(uncommented)
    lines = code.splitlines()
    uncommented_lines = uncommented.splitlines()
    original_lines = file.text.splitlines()
    findings: list[Finding] = []

    def add(*args, **kwargs):
        findings.append(_make(*args, **kwargs))

    # A credential rule requires a complete literal RHS in executable code.
    # It deliberately rejects expressions and string contents such as
    # logger.info("token=" + token).
    aws_credentials = re.compile(
        r"(?:new\s+)?(?:[A-Za-z0-9_$.]+\.)?BasicAWSCredentials\s*"
        r"\(\s*\"[^\"]+\"\s*,\s*\"[^\"]+\"\s*\)"
    )
    aws_environment_literal = re.compile(
        r'(?i)\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\b\s*=\s*"[^\"]{8,}"'
    )
    aws_access_key = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
    private_key_header = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
    logging_call = re.compile(
        r"(?i)(?:\b(?:log|logger|systemLogger|accessLogger|auditLogger)\s*\.\s*[A-Za-z_$][\w$]*|System\.(?:out|err)\.(?:print|println)|printStackTrace)\s*\("
    )
    for line_no, line in enumerate(lines, 1):
        window = "\n".join(lines[max(0, line_no - 2) : line_no + 2])
        original = original_lines[line_no - 1] if line_no <= len(original_lines) else line

        secret_line = (
            uncommented_lines[line_no - 1] if line_no <= len(uncommented_lines) else original
        )
        if _has_hardcoded_secret_assignment(secret_line):
            add(
                "WB.SECRET.HARDCODED",
                "Hardcoded Java secret candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=86,
                syntax="assignment",
                api="literal",
                cwes=["CWE-798"],
                reason="A credential-like Java assignment contains a literal secret.",
            )

        if aws_credentials.search(
            uncommented_lines[line_no - 1] if line_no <= len(uncommented_lines) else original
        ):
            add(
                "WB.SECRET.HARDCODED",
                "Hardcoded AWS credentials passed to BasicAWSCredentials",
                file,
                line_no,
                config,
                severity="low" if classify_code_surface(file.path) == "test" else "high",
                confidence=96,
                syntax="constructor_invocation",
                api="BasicAWSCredentials",
                source="literal access key and secret key",
                sink="AWS credential object",
                classification="high_confidence_candidate",
                verdict_candidate="high_confidence_candidate",
                sensitive_value="AWS access key and secret key (redacted)",
                cwes=["CWE-798"],
                reason="Literal AWS credentials are passed directly to the AWS credential constructor.",
            )
        elif (
            aws_environment_literal.search(secret_line)
            or aws_access_key.search(secret_line)
            or private_key_header.search(secret_line)
        ):
            add(
                "WB.SECRET.HARDCODED",
                "High-signal credential literal in Java source",
                file,
                line_no,
                config,
                severity="low" if classify_code_surface(file.path) == "test" else "high",
                confidence=94,
                syntax="literal_assignment",
                api="AWS credential/private-key literal",
                source="literal credential material",
                sink="source repository",
                classification="high_confidence_candidate",
                verdict_candidate="high_confidence_candidate",
                sensitive_value="credential material (redacted)",
                cwes=["CWE-798"],
                reason="A high-signal AWS credential identifier, access-key shape, or private-key header is present in active source code.",
            )

        if logging_call.search(line) and re.search(
            r"(?i)\b(?:token|access[_-]?token|refresh[_-]?token|accessToken|refreshToken|bearer|authorization|jwt|api[_-]?key|apiKey|secret|client[_-]?secret|clientSecret|password|passwd|credential|session[_-]?id|sessionId|cookie|sid|privateKey)\b",
            line,
        ):
            masking = bool(
                re.search(
                    r"(?i)(mask|redact|substring|last\s*4|\*{2,}|hash|encrypt|cipherencrypt)",
                    original,
                )
            )
            if masking:
                continue
            add(
                "WB.LOG.SENSITIVE_DATA",
                "Sensitive runtime value exposed through application logging",
                file,
                line_no,
                config,
                severity="medium",
                confidence=88,
                syntax="method_invocation",
                api="logging API",
                source="sensitive identifier in logging arguments",
                sink="logging method",
                classification="high_confidence_candidate",
                verdict_candidate="high_confidence_candidate",
                sensitive_value="sensitive runtime identifier (redacted)",
                logging_sink="logger/log/System.out",
                masking_detected=False,
                cwes=["CWE-532"],
                counterevidence=[],
                reason="A sensitive-looking runtime value appears as a logging argument; the complete value may be exposed.",
            )

        if re.search(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", line):
            controlled = bool(
                re.search(r"(?i)(request|input|param|body|query|header|user)", original)
            )
            add(
                "WB.EXEC.DYNAMIC",
                "Runtime.exec command execution candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=88 if controlled else 68,
                syntax="method_invocation",
                api="Runtime.getRuntime().exec",
                source="request-controlled input" if controlled else "unknown",
                sink="Runtime.exec",
                classification="high_confidence_candidate" if controlled else "review_lead",
                cwes=["CWE-78"],
                reason="Runtime.exec is actually invoked; argument provenance requires verification.",
            )
        elif re.search(r"\bnew\s+ProcessBuilder\s*\(", line):
            controlled = bool(
                re.search(r"(?i)(request|input|param|body|query|header|user)", original)
            )
            add(
                "WB.EXEC.DYNAMIC",
                "ProcessBuilder command execution candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=84 if controlled else 58,
                syntax="constructor_invocation",
                api="ProcessBuilder",
                source="request-controlled input" if controlled else "unknown",
                sink="ProcessBuilder",
                classification="high_confidence_candidate" if controlled else "review_lead",
                cwes=["CWE-78"],
                reason="ProcessBuilder is instantiated; fixed versus attacker-controlled command arguments require verification.",
            )
        elif re.search(r"\b(?:ScriptEngine|engine)\s*\.\s*eval\s*\(", line):
            add(
                "WB.EXEC.DYNAMIC",
                "Script engine evaluation candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=76,
                syntax="method_invocation",
                api="ScriptEngine.eval",
                sink="ScriptEngine.eval",
                cwes=["CWE-95"],
                reason="A script-engine eval invocation is present.",
            )

        if re.search(
            r"\.(?:execute|executeQuery|executeUpdate|query|update|createNativeQuery)\s*\(", line
        ) and re.search(r"(?i)\b(?:select|insert|update|delete)\b", original):
            dynamic = bool(
                re.search(
                    r"\+\s*(?:request|input|param|query|user|body|id)|String\.format|formatted\s*\(",
                    original,
                    re.I,
                )
            )
            safe_bind = bool(re.search(r"\?|:?[A-Za-z][A-Za-z0-9_]*\s*[,)]", original)) and bool(
                re.search(r"PreparedStatement|JdbcTemplate|createNativeQuery", line)
            )
            if dynamic and not safe_bind:
                api_match = re.search(
                    r"\.(execute\w*|query|update|createNativeQuery)\s*\(", line, re.I
                )
                add(
                    "WB.SQL.RAW_CONSTRUCTION",
                    "Dynamic SQL reaches an execution API",
                    file,
                    line_no,
                    config,
                    severity="high",
                    confidence=88,
                    syntax="method_invocation",
                    api=api_match.group(1) if api_match else "SQL execution",
                    source="request-controlled input"
                    if re.search(r"request|param|query|user", original, re.I)
                    else "unknown",
                    sink="SQL execution",
                    cwes=["CWE-89"],
                    classification="high_confidence_candidate",
                    reason="SQL-like data is dynamically constructed at an observable execution call.",
                )

        upload_sink = re.search(
            r"\b(?:transferTo|Files\.(?:copy|write)|FileOutputStream|putObject|upload|store)\s*\(",
            line,
        )
        original_name = re.search(r"getOriginalFilename\s*\(\s*\)", original)
        upload_context = _upload_source_context(uncommented_lines, line_no)
        has_upload_source = _has_uploaded_file_source(upload_context)
        if upload_sink and has_upload_source:
            controls = _has_control(window)
            validated = len(controls) >= 2
            utility_conversion = classify_code_surface(file.path) == "utility" and not original_name
            add(
                "WB.UPLOAD.UNSAFE",
                "MultipartFile conversion utility requires caller-context review"
                if utility_conversion
                else "Validated Java file upload/storage flow observed"
                if validated
                else "Java file upload or storage operation requires review",
                file,
                line_no,
                config,
                severity="informational" if utility_conversion or validated else "medium",
                confidence=25 if utility_conversion else 38 if validated else 62,
                syntax="method_invocation",
                api=upload_sink.group(0).strip(" ("),
                source="MultipartFile/Part or request file",
                sink="file or object storage",
                controls=controls,
                cwes=[] if utility_conversion or validated else ["CWE-434"],
                classification="review_point" if utility_conversion or validated else "review_lead",
                verdict_candidate="informational_inventory"
                if utility_conversion or validated
                else "secure_coding_concern",
                reason=(
                    "A utility converts a MultipartFile to a local File, but no endpoint, original-filename use, storage destination, or caller-controlled path is proven."
                    if utility_conversion
                    else "An actual upload/storage flow is present and multiple validation controls are visible."
                    if validated
                    else "An actual upload/storage operation is invoked; type, size, filename, and destination controls require review."
                ),
            )
        elif (
            original_name
            and has_upload_source
            and re.search(
                r"(?:Paths?\.get|FileOutputStream|putObject|transferTo|Files\.(?:copy|write))",
                window,
            )
        ):
            add(
                "WB.UPLOAD.ORIGINAL_FILENAME",
                "Original filename reaches a storage path or key",
                file,
                line_no,
                config,
                severity="high",
                confidence=78,
                syntax="method_invocation",
                api="getOriginalFilename plus storage operation",
                source="uploaded file metadata",
                sink="file/object storage path",
                controls=_has_control(window),
                cwes=["CWE-22", "CWE-434"],
                reason="Original client-provided filename appears near an actual storage operation without proven canonicalization or allowlisting.",
            )

        path_sink = re.search(
            r"\b(?:Files\.(?:read\w*|write\w*|delete\w*|copy)|File(?:Input|Output)Stream|File\.delete|Files\.delete|ZipInputStream|TarArchiveInputStream)\s*\(",
            line,
        )
        source_match = re.search(
            r"(?i)(request\s*\.\s*(?:getParameter|getHeader|getInputStream)|"
            r"@(?:RequestParam|PathVariable)|HttpServletRequest|"
            r"getOriginalFilename\s*\(\s*\)|request\s*\.(?:get|param|query|body))",
            original,
        )
        if path_sink and source_match:
            controls = _has_control(window)
            add(
                "WB.FILE.PATH_INPUT",
                "User-controlled input reaches a Java file/path operation",
                file,
                line_no,
                config,
                severity="low",
                confidence=45,
                syntax="method_invocation",
                api=path_sink.group(0).strip(" ("),
                source=source_match.group(0),
                sink="file/path operation",
                controls=controls,
                cwes=[],
                classification="review_point",
                verdict_candidate="review_point",
                reason="A possible request-derived value appears near a file/path operation, but complete containment and call-flow evidence are not established.",
                proof_gaps=[
                    "Complete source-to-sink flow and path containment require manual verification."
                ],
            )

        deserialize = re.search(
            r"\b(?:ObjectInputStream|XMLDecoder)\s*\.[A-Za-z0-9_]*readObject\s*\(|\breadObject\s*\(",
            line,
        )
        if deserialize and re.search(r"ObjectInputStream|XMLDecoder|readObject", window):
            add(
                "WB.DESERIALIZATION.UNSAFE",
                "Unsafe Java object deserialization candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=82,
                syntax="method_invocation",
                api="ObjectInputStream.readObject/XMLDecoder.readObject",
                source="serialized input",
                sink="native object deserialization",
                cwes=["CWE-502"],
                reason="A dangerous object deserialization method is actually invoked.",
            )

        if re.search(
            r"\b(?:NoopHostnameVerifier|TrustAll|InsecureTrustManagerFactory)\b", line
        ) and not re.search(r"^\s*(?:import|package)\b", line):
            add(
                "WB.CRYPTO.TLS_VERIFY_DISABLED",
                "Java TLS verification disabled candidate",
                file,
                line_no,
                config,
                severity="high",
                confidence=90,
                syntax="configuration_reference",
                api="NoopHostnameVerifier/TrustAll",
                sink="TLS client configuration",
                cwes=["CWE-295"],
                classification="confirmed_static_evidence",
                reason="An insecure TLS verification configuration is referenced in executable code.",
            )

        if re.search(r"\bnew\s+java\.util\.Random\s*\(|\bnew\s+Random\s*\(", line):
            add(
                "WB.RANDOM.PREDICTABLE",
                "Predictable Java randomness candidate",
                file,
                line_no,
                config,
                severity="medium",
                confidence=62,
                syntax="constructor_invocation",
                api="java.util.Random",
                sink="security-sensitive value if propagated",
                cwes=["CWE-330"],
                reason="java.util.Random is instantiated; security-sensitive use requires verification.",
            )

    return findings
