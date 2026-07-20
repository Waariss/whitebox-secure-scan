#!/usr/bin/env python3
"""Update the canonical Homebrew Formula from official PyPI metadata."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

FORMULA_PATH = (
    Path(__file__).resolve().parents[1] / "packaging/homebrew/Formula/whitebox-secure-scan.rb"
)
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
PYPI_URL = "https://pypi.org/pypi/whitebox-secure-scan/{version}/json"


def select_source_distribution(metadata: dict[str, object], version: str) -> tuple[str, str]:
    """Return the verified sdist URL and SHA256 for *version*."""
    releases = metadata.get("urls")
    if not isinstance(releases, list):
        raise ValueError("PyPI metadata does not contain release files")

    expected_name = f"whitebox_secure_scan-{version}.tar.gz"
    for release in releases:
        if not isinstance(release, dict):
            continue
        if release.get("packagetype") != "sdist" or release.get("filename") != expected_name:
            continue
        url = release.get("url")
        digests = release.get("digests")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(url, str) or not url.startswith("https://files.pythonhosted.org/"):
            raise ValueError("PyPI sdist URL is not an official files.pythonhosted.org URL")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("PyPI sdist does not contain a valid SHA256 digest")
        return url, sha256

    raise ValueError(f"No source distribution found for whitebox-secure-scan {version}")


def fetch_metadata(version: str) -> dict[str, object]:
    request = Request(
        PYPI_URL.format(version=version),
        headers={"User-Agent": "whitebox-secure-scan-homebrew-helper/1"},
    )
    with urlopen(request, timeout=20) as response:  # noqa: S310 - maintainer-only HTTPS metadata fetch
        payload = response.read()
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("PyPI response is not a JSON object")
    return parsed


def update_formula(path: Path, url: str, sha256: str) -> None:
    content = path.read_text(encoding="utf-8")
    updated_url, count = re.subn(
        r'(?m)^(\s*url\s+")[^"]+("\s*)$', rf"\g<1>{url}\g<2>", content, count=1
    )
    if count != 1:
        raise ValueError("could not find the Formula's main url declaration")
    updated_sha, count = re.subn(
        r'(?m)^(\s*sha256\s+")[^"]+("\s*)$', rf"\g<1>{sha256}\g<2>", updated_url, count=1
    )
    if count != 1:
        raise ValueError("could not find the Formula's main sha256 declaration")
    path.write_text(updated_sha, encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not VERSION_PATTERN.fullmatch(argv[1]):
        print(f"usage: {argv[0]} X.Y.Z", file=sys.stderr)
        return 2
    version = argv[1]
    try:
        url, sha256 = select_source_distribution(fetch_metadata(version), version)
        update_formula(FORMULA_PATH, url, sha256)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(FORMULA_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
