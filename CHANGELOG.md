# Changelog

## Unreleased

- Rules for GitHub Actions workflows (GA001 to GA009): unpinned third-party actions, a missing or `write-all` token scope, script injection from event data, `pull_request_target` checking out the PR head, secrets written into scripts, self-hosted runners on pull requests, missing job timeouts and `curl | sh`.
- Rules for Jenkins declarative pipelines (JK001 to JK007): literal credentials, `agent any`, no timeout, Groovy injection in double-quoted `sh` steps, unpinned images, a production deploy with no `input` approval and `curl | sh`.
- `check` picks the rule set from the file: Harness YAML, an Actions workflow, or a `Jenkinsfile*`. `rules` shows each rule's kind, `schema` skips files that are not Harness YAML, and suppression comments accept `//` as well as `#`.
- A second pre-commit hook, `harness-doctor-workflows`, for workflows and Jenkinsfiles.

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
