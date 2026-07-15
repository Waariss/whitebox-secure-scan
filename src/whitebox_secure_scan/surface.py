from pathlib import Path


def classify_code_surface(path: str | Path) -> str:
    parts = {part.lower() for part in Path(path).parts}
    text = str(path).lower()
    if "src/test" in text or "test" in parts or "tests" in parts or "fixture" in parts:
        return "test"
    if "generated" in parts or "build" in parts or "target" in parts:
        return "generated"
    if "middleware" in parts or "middlewares" in parts:
        return "middleware"
    if any(part in parts for part in ("frontend", "client", "components")):
        return "frontend"
    if any(part in parts for part in ("backend", "server", "controllers", "services")):
        return "backend"
    if "demo" in parts or "example" in parts:
        return "demo"
    if "util" in parts or "utility" in parts:
        return "utility"
    if any(part in parts for part in ("config", "configuration", "resources")):
        return "configuration"
    if "src/main" in text:
        return "production"
    return "unknown"
