from __future__ import annotations

import importlib.util
from pathlib import Path


def load_helper():
    path = Path(__file__).parents[1] / "scripts/update-homebrew-formula.py"
    spec = importlib.util.spec_from_file_location("update_homebrew_formula", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_select_source_distribution_rejects_missing_sdist() -> None:
    helper = load_helper()
    try:
        helper.select_source_distribution({"urls": []}, "1.1.0")
    except ValueError as error:
        assert "No source distribution" in str(error)
    else:
        raise AssertionError("missing sdist should fail safely")


def test_update_formula_changes_only_main_url_and_checksum(tmp_path: Path) -> None:
    helper = load_helper()
    formula = tmp_path / "formula.rb"
    formula.write_text(
        'url "https://old.example/project-1.0.0.tar.gz"\n'
        'sha256 "' + "0" * 64 + '"\n'
        '\nresource "dependency" do\n'
        '  url "https://dependency.example/archive.tar.gz"\n'
        '  sha256 "' + "1" * 64 + '"\nend\n',
        encoding="utf-8",
    )
    helper.update_formula(formula, "https://files.pythonhosted.org/project-1.1.0.tar.gz", "2" * 64)
    result = formula.read_text(encoding="utf-8")
    assert 'url "https://files.pythonhosted.org/project-1.1.0.tar.gz"' in result
    assert 'sha256 "' + "2" * 64 + '"' in result
    assert 'url "https://dependency.example/archive.tar.gz"' in result
    assert 'sha256 "' + "1" * 64 + '"' in result
