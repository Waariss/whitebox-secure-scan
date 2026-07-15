from pathlib import Path

RULE_SCHEMA = {
    "type": "object",
    "required": ["rules"],
    "properties": {
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "title", "category", "severity", "confidence"],
            },
        }
    },
}


def load_rules(directory: Path | None) -> list[dict]:
    if not directory:
        return []
    rules = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            import yaml  # type: ignore[import-untyped]  # Optional dependency is declared at runtime.

            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rules.extend(loaded.get("rules", []))
        except (OSError, ValueError):
            continue
    return rules


def validate_rules(directory: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not directory.is_dir():
        return False, [f"rules directory does not exist: {directory}"]
    try:
        import yaml
        from jsonschema import Draft202012Validator  # type: ignore[import-untyped]  # Optional dependency.
    except ImportError:
        # Keep doctor/validation useful in a minimal offline environment. Full
        # JSON Schema validation is used whenever the declared dependencies exist.
        for path in sorted(directory.glob("*.yaml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "rules:" not in text:
                errors.append(f"{path.name}: missing rules")
            for required in (
                "id:",
                "title:",
                "description:",
                "category:",
                "severity:",
                "confidence:",
            ):
                if required not in text:
                    errors.append(f"{path.name}: missing required field {required[:-1]}")
        return not errors, errors
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            errors.extend(
                f"{path.name}: {e.message}"
                for e in Draft202012Validator(RULE_SCHEMA).iter_errors(data)
            )
        except Exception as exc:
            errors.append(f"{path.name}: {exc}")
    return not errors, errors
