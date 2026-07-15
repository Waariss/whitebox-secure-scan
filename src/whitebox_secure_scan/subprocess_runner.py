from dataclasses import dataclass
import subprocess
import tempfile


@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str


def run_local(argv: list[str], cwd, timeout: int, env: dict[str, str]) -> Completed:
    """Run an explicitly enabled local tool with bounded captured output."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            argv, cwd=cwd, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, env=env
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise TimeoutError(f"local tool exceeded {timeout}s")
        stdout.seek(0)
        stderr.seek(0)
        return Completed(
            process.returncode,
            stdout.read(65536).decode("utf-8", errors="replace"),
            stderr.read(65536).decode("utf-8", errors="replace"),
        )
