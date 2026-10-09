# Changelog

## Unreleased

- `--format github` prints inline PR annotations, a pre-commit hook is provided, and tests must keep coverage at or above 90%.

## v0.1.0

- Nine lint rules (HD001 to HD009) for Harness pipelines, templates and triggers, with text, JSON and SARIF output.
- `schema` command validates files against Harness's published JSON schema.
- GitHub Action and a Harness Governance OPA policy.
- `.harness/` holds the pipelines, template and triggers that build this repo.
