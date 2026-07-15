from dataclasses import dataclass
from pathlib import Path
import shutil
from .models import Finding
from .subprocess_runner import run_local


@dataclass
class AdapterResult:
    findings: list[Finding]
    errors: list[str]


SUPPORTED = {"semgrep", "gitleaks", "trivy", "bandit", "gosec", "findsecbugs"}


def run_local_adapter(name: str, root: Path, timeout: int = 30) -> AdapterResult:
    executable = shutil.which(name)
    if name not in SUPPORTED or executable is None:
        return AdapterResult([], [f"adapter unavailable or unsupported: {name}"])
    # Adapters intentionally require explicit integration and never use a shell.
    try:
        proc = run_local(
            [name, "--version"],
            cwd=root,
            timeout=timeout,
            env={"PATH": str(Path(executable).parent)},
        )
        if proc.returncode != 0:
            return AdapterResult([], [f"{name} exited {proc.returncode}"])
        return AdapterResult([], [])
    except (OSError, TimeoutError) as exc:
        return AdapterResult([], [f"{name}: {exc}"])
