# Contributing

## Setup

```
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check src tests
opa test --v0-compatible policies
```

## Adding a rule

1. Write a function in `src/harness_doctor/rules.py` decorated with `@rule(id, severity, title, why)`. It yields `(line, message, hint)`.
2. Add a passing and a failing case to `tests/test_rules.py`. Parametrize the edge cases.
3. If it belongs in the Harness policy, add it to `policies/pipeline_guardrails.rego` with a test.
4. Add a row to the README table and a line to `CHANGELOG.md`.

A rule should flag something that has caused an incident or a leak, and the `why` should say how. Avoid style opinions.

## Pull requests

Branch from `main`, keep the change small, and make sure CI is green. Coverage must stay at or above 90%. Commit messages are one short line saying what changed.
