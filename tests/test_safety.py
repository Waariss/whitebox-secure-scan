import hashlib
import socket
from pathlib import Path

import pytest

from whitebox_secure_scan.cli import main
from whitebox_secure_scan.repository import walk_repository

FIXTURES = Path(__file__).parent / "fixtures"


def snapshot(root: Path):
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        stat = path.stat()
        result[str(path.relative_to(root))] = (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_mode,
        )
    return result


def test_target_immutability_and_no_network(monkeypatch, tmp_path):
    target = tmp_path / "synthetic repo; $safe"
    target.mkdir()
    (target / "main.py").write_text("API_KEY = 'synthetic-secret-123456'\n", encoding="utf-8")
    before = snapshot(target)

    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    output = tmp_path / "results"
    with pytest.raises(SystemExit) as result:
        main_args = ["whitebox-secure-scan", "scan", str(target), "--output", str(output)]
        monkeypatch.setattr("sys.argv", main_args)
        main()
    assert result.value.code == 0
    assert snapshot(target) == before
    values = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in output.iterdir())
    assert "synthetic-secret-123456" not in values


def test_output_boundary_and_symlink_rejection(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("print('synthetic')", encoding="utf-8")
    with pytest.raises(SystemExit) as result:
        import sys

        old = sys.argv
        sys.argv = ["whitebox-secure-scan", "scan", str(target), "--output", str(target / "output")]
        try:
            main()
        finally:
            sys.argv = old
    assert result.value.code == 2
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SystemExit):
        import sys

        old = sys.argv
        sys.argv = ["whitebox-secure-scan", "scan", str(target), "--output", str(link)]
        try:
            main()
        finally:
            sys.argv = old


def test_handoff_contract(tmp_path, monkeypatch):
    import sys

    target = FIXTURES / "vulnerable"
    result_dir = tmp_path / "results"
    old = sys.argv
    sys.argv = ["whitebox-secure-scan", "scan", str(target), "--output", str(result_dir)]
    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old
    handoff = tmp_path / "handoff"
    sys.argv = ["whitebox-secure-scan", "handoff", str(result_dir), "--output", str(handoff)]
    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old
    for name in (
        "findings.json",
        "inventory.json",
        "routes.json",
        "scan-metadata.json",
        "AI_REVIEW_PROMPT.md",
        "context-request.json",
        "HANDOFF_README.md",
    ):
        assert (handoff / name).is_file()
    assert not list(handoff.rglob("*.py"))


def test_gitignored_test_source_remains_available_for_secret_review(tmp_path: Path):
    test_dir = tmp_path / "src" / "test" / "java"
    test_dir.mkdir(parents=True)
    (tmp_path / ".gitignore").write_text("src/test/\n", encoding="utf-8")
    (test_dir / "TestCredentials.java").write_text(
        'class TestCredentials { Object x = new BasicAWSCredentials("AKIA1234567890ABCDEF", "synthetic-secret-key"); }\n',
        encoding="utf-8",
    )
    result = walk_repository(tmp_path, respect_gitignore=True)
    assert any(file.path.name == "TestCredentials.java" for file in result.files)
