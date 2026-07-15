import os
from dataclasses import dataclass, field
from pathlib import Path
from .surface import classify_code_surface

DEFAULT_EXCLUDED = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "out",
    "generated",
    "tmp",
    "cache",
}
EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
}


@dataclass(frozen=True)
class SourceFile:
    path: Path
    language: str
    text: str
    size: int = 0
    code_surface: str = "unknown"


@dataclass
class WalkResult:
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    parser_errors: list[dict] = field(default_factory=list)

    def __iter__(self):
        return iter(self.files)

    def __len__(self):
        return len(self.files)

    def __eq__(self, other):
        if isinstance(other, list):
            return self.files == other
        return super().__eq__(other)


def _ignored(rel: Path, names: set[str], gitignore: set[str]) -> bool:
    # Test-source secrets remain reportable even when a repository's gitignore
    # excludes test output or test directories. Generated/dependency defaults
    # still take precedence through `names`.
    if any(part.lower() in {"test", "tests", "__tests__"} for part in rel.parts):
        return any(part in names for part in rel.parts)
    return any(part in names for part in rel.parts) or any(
        str(rel) == item or item in rel.parts for item in gitignore
    )


def walk_repository(
    root: Path,
    excludes: set[str] | None = None,
    max_file_size: int = 2_000_000,
    respect_gitignore: bool = False,
) -> WalkResult:
    root = root.resolve()
    excluded = DEFAULT_EXCLUDED | (excludes or set())
    gitignore = set()
    if respect_gitignore and (root / ".gitignore").is_file():
        gitignore = {
            line.strip().strip("/")
            for line in (root / ".gitignore").read_text(errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        }
    result = WalkResult()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            result.skipped.append(
                {"path": str(current.relative_to(root)), "reason": f"unreadable: {exc}"}
            )
            continue
        for entry in entries:
            path = Path(entry.path)
            rel = path.relative_to(root)
            try:
                if entry.is_symlink():
                    result.skipped.append({"path": str(rel), "reason": "symlink not followed"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if _ignored(rel, excluded, gitignore):
                        result.skipped.append({"path": str(rel), "reason": "excluded directory"})
                    else:
                        stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                language = EXTENSIONS.get(path.suffix.lower())
                if not language:
                    continue
                size = entry.stat(follow_symlinks=False).st_size
                if size > max_file_size:
                    result.skipped.append({"path": str(rel), "reason": "maximum file size"})
                    continue
                raw = path.read_bytes()
                if b"\x00" in raw[:8192]:
                    result.skipped.append({"path": str(rel), "reason": "binary file"})
                    continue
                result.files.append(
                    SourceFile(
                        rel,
                        language,
                        raw.decode("utf-8", errors="replace"),
                        size,
                        classify_code_surface(root / rel),
                    )
                )
            except (OSError, ValueError) as exc:
                result.skipped.append({"path": str(rel), "reason": f"read failure: {exc}"})
    result.files.sort(key=lambda item: str(item.path))
    return result


def inventory_manifests(root: Path) -> list[str]:
    names = {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "go.sum",
        "Dockerfile",
        "docker-compose.yml",
        "k8s.yaml",
        "deployment.yaml",
    }
    return sorted(
        str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p.name in names
    )
