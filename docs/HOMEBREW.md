# Homebrew distribution

`whitebox-secure-scan` is distributed through the Waariss tap for macOS. The
Formula installs the core scanner locally and does not execute target
repositories or contact external services during a scan.

## Installation

```bash
brew install waariss/tap/whitebox-secure-scan
```

## Upgrade

```bash
brew update
brew upgrade whitebox-secure-scan
```

## Uninstall

```bash
brew uninstall whitebox-secure-scan
```

## Verification

```bash
whitebox-secure-scan version
whitebox-secure-scan --help
whitebox-secure-scan doctor
```

## Core scanner limitation

The initial Homebrew Formula installs the core scanner only. It does not
include the optional `parsing` extra (`tree-sitter` and
`tree-sitter-languages`). The core scanner remains functional without those
optional dependencies. Users who need the parsing extra should use the
supported PyPI installation method documented in the main README.

## Maintainer workflow

1. Publish and verify the PyPI release.
2. Update the canonical Formula in `packaging/homebrew/Formula`.
3. Generate or refresh Python resources when runtime dependencies change.
4. Run Formula style, audit, install, and test validation.
5. Copy the tested Formula to `Waariss/homebrew-tap`.
6. Test a clean public installation from the tap.

The Formula is intentionally maintained separately from scanner security
analysis. No tag, release, or package publication is performed by the Formula
update helper.
