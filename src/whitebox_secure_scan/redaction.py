import re

SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|private[_-]?key|authorization|cookie)\s*[:=]\s*(['\"]?)([^\s'\";,]{8,})\2"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S
)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
BASIC_CREDENTIALS_RE = re.compile(
    r"(BasicAWSCredentials\s*\(\s*\")([^\"]+)(\"\s*,\s*\")([^\"]+)(\")"
)


def redact(text: str) -> str:
    text = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = AWS_KEY_RE.sub(lambda m: f"{m.group(0)[:4]}********{m.group(0)[-2:]}", text)
    text = BASIC_CREDENTIALS_RE.sub(r"\1[REDACTED ACCESS KEY]\3[REDACTED SECRET KEY]\5", text)
    return SECRET_RE.sub(lambda m: f"{m.group(1)}={m.group(3)[:3]}********{m.group(3)[-2:]}", text)


def snippet(lines: list[str], line: int, enabled: bool, maximum: int, redact_enabled: bool) -> str:
    if not enabled:
        return ""
    start = max(0, line - 1)
    value = "\n".join(lines[start : start + max(1, maximum)])
    return redact(value) if redact_enabled else value
