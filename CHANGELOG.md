# Changelog

## v0.1.1

- The Action now prints GitHub annotations, so findings appear on the pull request. It printed plain text before.
- A YAML parse error no longer leaves a broken SARIF file that fails the upload step a second time.
- A failed SARIF upload (fork pull requests, repos without code scanning) no longer fails the job.
- The schema step still runs when lint fails.
- CI runs the Action on this repo's own pipelines.
- `.coverage` is no longer tracked.

## v0.1.0

- Nine lint rules (HD001 to HD009) for Harness pipelines, templates and triggers, with text, JSON, SARIF and GitHub annotation output.
- `schema` validates files against Harness's published JSON schema and points at the offending line.
- A GitHub Action, a pre-commit hook, and a Harness Governance OPA policy with tests.
- `.harness/` holds the pipelines, template and triggers that build this repo, and harness-doctor lints them on every run.
- CodeQL, gitleaks, pip-audit and weekly Dependabot run on every change. Releases carry signed build provenance and a checksum file.
