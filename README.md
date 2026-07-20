# whitebox-secure-scan

[![PyPI](https://img.shields.io/pypi/v/whitebox-secure-scan?logo=pypi&logoColor=white)](https://pypi.org/project/whitebox-secure-scan/)
[![Python](https://img.shields.io/pypi/pyversions/whitebox-secure-scan)](https://pypi.org/project/whitebox-secure-scan/)
[![Tests](https://github.com/Waariss/whitebox-secure-scan/actions/workflows/test.yml/badge.svg)](https://github.com/Waariss/whitebox-secure-scan/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/Waariss/whitebox-secure-scan/blob/main/LICENSE)

![whitebox-secure-scan banner](https://raw.githubusercontent.com/Waariss/whitebox-secure-scan/main/docs/assets/whitebox-secure-scan-banner.svg)

`whitebox-secure-scan` is a local, offline white-box secure-code triage tool for penetration testers. It helps you filter a large codebase into explainable review leads, precise file and line evidence, grouped root causes, and reviewer guidance.

It is a triage aid—not a final penetration-test report and not an automatic vulnerability confirmer. Every candidate must be independently verified by an authorized security engineer.

The analysis stays local: source enters a bounded review pipeline, evidence is grouped for a human reviewer, and no source is sent to an external service.

![Local code review and evidence grouping](https://raw.githubusercontent.com/Waariss/whitebox-secure-scan/main/docs/assets/whitebox-secure-scan-overview.png)

## Quick start

Run the latest published package without installing it globally:

```bash
uvx whitebox-secure-scan@latest version
uvx whitebox-secure-scan@latest review /path/to/repository \
  --output ./whitebox-results
```

Keep the output directory outside the target repository. The scanner reads target source locally, does not execute it, and does not modify it.

## Installation

### Run with `uvx` — recommended

`uvx` runs the published package in an isolated environment and does not require a permanent installation.

```bash
uvx whitebox-secure-scan@latest version
uvx whitebox-secure-scan@latest --help
uvx whitebox-secure-scan@latest review /path/to/repository \
  --output ./whitebox-results
uvx whitebox-secure-scan@1.0.1 version
```

### Install with `pip`

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install whitebox-secure-scan
whitebox-secure-scan version
whitebox-secure-scan review /path/to/repository \
  --output ./whitebox-results
```

Upgrade an existing installation with:

```bash
python -m pip install --upgrade whitebox-secure-scan
```

The package supports Python 3.11 and newer. `uvx` and `pip` use the published PyPI package; no repository checkout is required for normal use.

### Install with Homebrew — macOS

The Formula is prepared for `Waariss/homebrew-tap` and will be available after
that Formula is merged and its public installation is validated:

```bash
brew install waariss/tap/whitebox-secure-scan
whitebox-secure-scan version
whitebox-secure-scan doctor
```

The Homebrew Formula installs the core scanner without the optional `parsing`
extra. Use the PyPI installation above when local Tree-sitter parser support is
needed. See the [Homebrew distribution guide](https://github.com/Waariss/whitebox-secure-scan/blob/main/docs/HOMEBREW.md).

### Optional parsing dependencies

The core scanner works without optional parsers. Install the local parsing extras when you want the additional parser support:

```bash
python -m pip install "whitebox-secure-scan[parsing]"
```


## What you get

The normal `review` command writes a concise, reviewer-first result set:

| File | Purpose |
| --- | --- |
| `SUMMARY.md` | Fast overview of root causes, locations, and scope |
| `report.md` | Detailed evidence and verification guidance |
| `findings.json` | Normalized finding instances for automation |
| `root-causes.json` | Related instances grouped for efficient review |
| `review-points.json` | Lower-confidence items that need context |

Advanced compatibility commands can also produce inventory, routes, metadata, SARIF, and a bounded internal-AI handoff package.

Local result files from supported tools can be imported without executing them:

```bash
whitebox-secure-scan review /path/to/repository \
  --import-result semgrep=/path/to/semgrep.json \
  --output ./whitebox-results
```

Supported import formats include Semgrep, Gitleaks, Bandit, gosec, and FindSecBugs. Imported results retain the external tool and rule IDs and are still review candidates.

![whitebox-secure-scan workflow](https://raw.githubusercontent.com/Waariss/whitebox-secure-scan/main/docs/assets/whitebox-secure-scan-workflow.svg)

## What it does—and does not do

| It does | It does not |
| --- | --- |
| Scan Python, JavaScript/TypeScript, Java, and Go source locally | Execute application code, tests, builds, migrations, or package scripts |
| Identify security review leads and review points | Claim that a finding is exploitable or confirmed |
| Preserve file, line, source, sink, and proof-gap context | Replace manual code review or a penetration tester |
| Group related evidence into root causes | Upload source, findings, telemetry, or analytics |
| Work offline by default | Call external AI services or download rules during a scan |

## Safety boundaries

The scanner is designed for controlled white-box review:

- Offline operation is enabled by default.
- Target repositories are treated as read-only.
- Repository code and commands are never executed.
- External scanners are disabled unless explicitly enabled and already installed locally.
- Output paths are safety-checked and should be outside the target repository.
- Symlinks that escape the target are not followed.
- Secrets are redacted by default and snippets are bounded.
- No source code or scan results are sent to a cloud service.

Only scan repositories you are authorized to review.

## Supported languages

- Python
- JavaScript and TypeScript, including common Node.js and frontend patterns
- Java, including common Spring-oriented patterns
- Go

Framework evidence is reported only when it is observable in the repository. Static analysis is intentionally conservative: incomplete flows remain review leads or review points.

When the optional parsing extra is installed, the parser layer can use local Tree-sitter grammars for JavaScript, TypeScript, Java, and Go. Without it, the scanner uses a structured lexical fallback. The code graph is bounded to observable declarations, routes, and calls; it is not complete whole-program interprocedural taint analysis.

## Typical workflow

```text
Scan locally
    ↓
Read SUMMARY.md and grouped root causes
    ↓
Inspect the referenced file and line
    ↓
Verify the complete flow manually
    ↓
Write the approved security finding, if confirmed
```

## Development installation

Use this section only when contributing to the project or running its synthetic test suite:

```bash
git clone https://github.com/Waariss/whitebox-secure-scan.git
cd whitebox-secure-scan
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
ruff check .
ruff format --check .
mypy src
```

Tests use synthetic fixtures. Do not point the test suite or examples at repositories you do not own or have permission to review. See [CONTRIBUTING.md](https://github.com/Waariss/whitebox-secure-scan/blob/main/CONTRIBUTING.md) and the [technical reference](https://github.com/Waariss/whitebox-secure-scan/blob/main/docs/REFERENCE.md).

## Documentation and support

- [Technical reference](https://github.com/Waariss/whitebox-secure-scan/blob/main/docs/REFERENCE.md)
- [Security boundaries](https://github.com/Waariss/whitebox-secure-scan/blob/main/SECURITY.md)
- [Contributing](https://github.com/Waariss/whitebox-secure-scan/blob/main/CONTRIBUTING.md)
- [Report a security issue](https://github.com/Waariss/whitebox-secure-scan/blob/main/SECURITY.md)
- [GitHub issues](https://github.com/Waariss/whitebox-secure-scan/issues)

## License

Apache License 2.0. See [LICENSE](https://github.com/Waariss/whitebox-secure-scan/blob/main/LICENSE).
