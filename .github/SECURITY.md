# Security Policy

## Supported versions

Fixes go into the latest release. Older releases are not patched.

## Reporting a vulnerability

Do not open a public issue. Report it privately through [GitHub Security Advisories](https://github.com/gerardrecinto/harness-doctor/security/advisories/new).

Include the affected version, a pipeline file or command that reproduces it, and the impact you see. Expect an acknowledgement within a few business days.

## What harness-doctor does and doesn't do

- It reads YAML with `yaml.SafeLoader` and never executes pipeline content.
- The `schema` command downloads Harness's published JSON schema from `raw.githubusercontent.com/harness/harness-schema` over HTTPS and caches it under `~/.cache/harness-doctor`. `check` makes no network calls.
- It is a linter. A clean run does not mean a pipeline is safe.

## Controls on this repo

Every push and pull request runs CodeQL, gitleaks and `pip-audit`. Dependabot raises weekly updates for pip and GitHub Actions. Release artifacts carry signed build provenance.
