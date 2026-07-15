from dataclasses import dataclass
from pathlib import Path
import os
import yaml  # type: ignore[import-untyped]  # PyYAML has no bundled typing in minimal environments.


@dataclass
class ScanConfig:
    offline: bool = True
    redact: bool = True
    snippets: bool = True
    max_snippet_lines: int = 3
    includes: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    min_confidence: int = 0
    max_file_size: int = 2_000_000
    timeout: int = 30
    no_git_history: bool = True
    disable_external_tools: bool = True
    external_tools: tuple[str, ...] = ()
    local_rules: Path | None = None
    respect_gitignore: bool = False
    execute_repository_code: bool = False
    fail_on: str | None = None
    production_only: bool = False
    include_test_code: bool = False
    include_test_secrets: bool = True
    include_test_review_points: bool = True
    show_suppressed: bool = False
    result_types: tuple[str, ...] = ()
    minimum_evidence_level: int = 0
    root_causes_only: bool = False
    exclude_inventory: bool = False
    show_review_points: bool = True


def parse_csv(values: str | list[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    source = [values] if isinstance(values, str) else values
    return tuple(x.strip() for value in source for x in value.split(",") if x.strip())


SAFE_KEYS = {
    "version",
    "review",
    "scope",
    "reporting",
    "test_code",
    "analysis",
}
UNSAFE_KEYS = {
    "offline",
    "network",
    "telemetry",
    "execute_repository_code",
    "redact",
    "upload",
    "install",
    "external_ai",
}


def load_review_config(target: Path, explicit: str | None = None) -> dict:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(target / ".whitebox-secure-scan.yml")
    candidates.append(
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "whitebox-secure-scan"
        / "config.yml"
    )
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        return {}
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid configuration {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a mapping")
    unknown = set(value) - SAFE_KEYS
    if unknown or any(key in value for key in UNSAFE_KEYS):
        raise ValueError("configuration contains unknown or non-configurable safety properties")
    if value.get("version", 1) != 1:
        raise ValueError("unsupported configuration version")
    for section in ("review", "scope", "reporting", "test_code", "analysis"):
        if section in value and not isinstance(value[section], dict):
            raise ValueError(f"configuration section {section} must be a mapping")
    return value
