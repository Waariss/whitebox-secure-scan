from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import os
import subprocess
import signal


MAX_CAPTURE_BYTES = 65_536


@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str


def _read_capped(stream) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_CAPTURE_BYTES
    while True:
        chunk = stream.read(8192)
        if not chunk:
            return b"".join(chunks)
        if remaining:
            kept = chunk[:remaining]
            chunks.append(kept)
            remaining -= len(kept)


def run_local(argv: list[str], cwd, timeout: int, env: dict[str, str]) -> Completed:
    """Run an explicitly enabled local tool with bounded captured output."""
    if timeout <= 0:
        raise ValueError("local tool timeout must be positive")
    kwargs = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "env": env,
    }
    if os.name != "nt":
        kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **kwargs)
    assert process.stdout is not None and process.stderr is not None
    with ThreadPoolExecutor(max_workers=2) as pool:
        stdout_future = pool.submit(_read_capped, process.stdout)
        stderr_future = pool.submit(_read_capped, process.stderr)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            raise TimeoutError(f"local tool exceeded {timeout}s")
        return Completed(
            process.returncode,
            stdout_future.result().decode("utf-8", errors="replace"),
            stderr_future.result().decode("utf-8", errors="replace"),
        )
