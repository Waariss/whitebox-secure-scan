# whitebox-secure-scan

`whitebox-secure-scan` is an offline, read-only white-box secure-code triage tool for penetration testers. It identifies high-signal security review leads, records precise file and line evidence, groups related instances into root causes, and provides reviewer guidance.

It is designed to accelerate source-code review not to replace a penetration tester, confirm exploitability automatically, or generate a final pentest report. Every candidate requires independent verification by an authorized security engineer.

It scans Python 3.11+, JavaScript/TypeScript, Java, and Go locally. It does not import, execute, upload, or modify target code and does not contact package registries or external AI services during scans.

## Install and run

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
whitebox-secure-scan review /path/to/repository --output ./whitebox-results
```

The normal `review` workflow keeps only the useful review outputs: `SUMMARY.md`, `report.md`, `findings.json`, `root-causes.json`, and `review-points.json`. Detailed inventory, routes, metadata, SARIF, and handoff packaging remain available through advanced compatibility commands. Results are review leads, not automatic vulnerability confirmations.

## Scope

The engine combines Python AST parsing, structured lexical analysis for the other supported languages, framework evidence detection, conservative source/sink heuristics, secret redaction, confidence scoring, duplicate suppression, route inventory, normalized reporting, safety-bounded walking, and local adapter interfaces. Findings are review leads or review points, not confirmed vulnerabilities.

Java uses a structured lexical fallback that removes comments/Javadocs, masks string literals for API matching, and requires observable method or constructor invocation. It distinguishes code surfaces such as production, test, utility, demo, generated, and configuration. Findings include `verdict_candidate`, `code_surface`, `proof_gaps`, `counterevidence`, parser metadata, and source/sink diagnostics.

JavaScript and TypeScript use the same conservative structured-lexical approach when an optional AST parser is unavailable. Upload findings require both an uploaded-file source and a write/storage sink; blob responses, report downloads, browser exports, API wrappers, identifiers, comments, and UI labels are not upload or execution evidence. Dynamic execution requires an invocation of `eval`, `Function`, `vm`, or a `child_process` API. Literal-secret findings require a credential-shaped value, while environment-variable lookups and labels such as `Change Password` are excluded.

The normal command is `whitebox-secure-scan review /path/to/repository`. Other commands are advanced support utilities. See [the compact technical reference](docs/REFERENCE.md).

Triage commands are `sample-unreported` for deterministic negative-review candidates and `compare` for old/new result comparison. Use `--production-only` for production results, `--include-test-code` to inspect ordinary test code, `--include-test-secrets` to retain test-source secrets, and `--root-causes-only` when consuming grouped results.

The operational workflow is: scan to an output directory outside the target, inspect the concise summary and evidence, optionally send the bounded handoff package to an approved internal verifier, then manually validate candidates. Default controls are offline operation, redaction, no repository execution, no external tools, bounded file reads, no symlink following, and no writes to the target repository.
