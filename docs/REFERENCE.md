# whitebox-secure-scan reference

## Product role

`whitebox-secure-scan` is an offline white-box secure-code triage tool for penetration testers. It finds high-signal security-sensitive code, records the relative path and line, explains source/sink evidence, groups related instances, and produces reviewer guidance.

It does not confirm exploitability, replace manual review, execute target code, access the network, upload source, or perform runtime testing.

## Result model

- **Review lead:** suspicious code that needs verification.
- **Review point:** incomplete source/sink or control evidence.
- **Root cause:** grouped underlying concern.
- **Instance:** one route, caller, line, or API occurrence related to a root cause.
- **Test observation:** result from test/demo code, kept separate from production observations.

Results contain a rule ID, relative location, code evidence, source, sink, controls, confidence, proof gaps, and counterevidence. A dangerous API mention without a demonstrated flow is an inventory observation or review point, not a confirmed issue.

## Output

The default result root is intentionally small: `SUMMARY.md`, `report.md`, `findings.json`, `root-causes.json`, and `review-points.json`. `SUMMARY.md` is the first file to read. Detailed inventory, SARIF, and handoff packaging are advanced compatibility features.

## Safety

Scanned repositories are untrusted, read-only input. The scanner does not follow symlinks outside the target, execute repository commands, install dependencies, call package managers, make network requests, load remote rules, or disable redaction.
