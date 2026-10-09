import json
import textwrap
from pathlib import Path

import pytest
import yaml

from harness_doctor.cli import main
from harness_doctor.engine import check_file

ROOT = Path(__file__).resolve().parent.parent


def lint(tmp_path, body: str, **kw):
    f = tmp_path / "p.yaml"
    f.write_text(textwrap.dedent(body))
    return check_file(f, **kw)


def ids(findings):
    return [f.rule for f in findings]


def ci_step(extra: str = "", timeout: str = "timeout: 5m") -> str:
    return f"""
    pipeline:
      identifier: p
      stages:
        - stage:
            identifier: s
            type: CI
            spec:
              caching:
                enabled: true
              execution:
                steps:
                  - step:
                      type: Run
                      identifier: r
                      {timeout}
                      spec:
{textwrap.indent(textwrap.dedent(extra), ' ' * 24)}
    """


def test_clean_step_has_no_findings(tmp_path):
    assert lint(tmp_path, ci_step("command: make test")) == []


def test_missing_timeout(tmp_path):
    assert ids(lint(tmp_path, ci_step("command: make", timeout=""))) == ["HD002"]


def test_literal_env_secret(tmp_path):
    body = ci_step("command: make\nenvVariables:\n  API_TOKEN: abc")
    assert ids(lint(tmp_path, body)) == ["HD001"]


def test_secret_reference_is_fine(tmp_path):
    body = ci_step('command: make\nenvVariables:\n  API_TOKEN: <+secrets.getValue("t")>')
    assert lint(tmp_path, body) == []


def test_string_variable_with_literal_secret(tmp_path):
    findings = lint(
        tmp_path,
        """
        pipeline:
          identifier: p
          variables:
            - name: db_password
              type: String
              value: hunter2
            - name: region
              type: String
              value: us-east-1
        """,
    )
    assert ids(findings) == ["HD001"]


def test_credential_shaped_string(tmp_path):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    findings = lint(tmp_path, ci_step(f"command: echo {key}"))
    assert ids(findings) == ["HD001"]


@pytest.mark.parametrize(
    "image,flagged",
    [
        ("node", True),
        ("node:latest", True),
        ("ghcr.io/acme/tool", True),
        ("node:22.9-slim", False),
        ("localhost:5000/tool:1.2", False),
        ("node@sha256:" + "a" * 64, False),
        ("<+pipeline.variables.image>", False),
    ],
)
def test_image_pinning(tmp_path, image, flagged):
    findings = lint(tmp_path, ci_step(f"image: {image}\ncommand: make"))
    assert ("HD003" in ids(findings)) is flagged


def test_pipe_to_shell(tmp_path):
    body = ci_step("command: curl -fsSL https://x.dev/i.sh | sudo bash")
    assert ids(lint(tmp_path, body)) == ["HD006"]


def test_curl_to_file_is_fine(tmp_path):
    assert lint(tmp_path, ci_step("command: curl -fsSLo i.sh https://x.dev/i.sh")) == []


@pytest.mark.parametrize("expr", ["<+codebase.branch>", "<+trigger.prTitle>", "<+trigger.payload.head_commit.message>"])
def test_script_injection(tmp_path, expr):
    assert ids(lint(tmp_path, ci_step(f"command: echo {expr}"))) == ["HD007"]


def test_untrusted_value_through_env_is_fine(tmp_path):
    body = ci_step('command: echo "$B"\nenvVariables:\n  B: <+codebase.branch>')
    assert lint(tmp_path, body) == []


def test_privileged(tmp_path):
    assert ids(lint(tmp_path, ci_step("command: make\nprivileged: true"))) == ["HD008"]


def test_ci_stage_without_cache(tmp_path):
    body = ci_step("command: make")
    assert "HD009" not in ids(lint(tmp_path, body))
    uncached = body.replace("caching:", "other:")
    assert "HD009" in ids(lint(tmp_path, uncached))


def deploy(env: str, approval: bool, rollback: bool) -> str:
    stages = []
    if approval:
        stages.append({"stage": {"identifier": "approve", "type": "Approval", "spec": {}}})
    stage = {
        "identifier": "deploy",
        "type": "Deployment",
        "spec": {"environment": {"environmentRef": env}},
    }
    if rollback:
        stage["failureStrategies"] = [
            {"onFailure": {"errors": ["AllErrors"], "action": {"type": "StageRollback"}}}
        ]
    stages.append({"stage": stage})
    return yaml.safe_dump({"pipeline": {"identifier": "p", "stages": stages}})


@pytest.mark.parametrize(
    "env,approval,expected",
    [
        ("prod", False, True),
        ("us_prod", False, True),
        ("production", False, True),
        ("prod", True, False),
        ("staging", False, False),
        ("preprod", False, False),
        ("non_prod", False, False),
    ],
)
def test_prod_needs_approval(tmp_path, env, approval, expected):
    findings = lint(tmp_path, deploy(env, approval, rollback=True))
    assert ("HD005" in ids(findings)) is expected


def test_rollback_required(tmp_path):
    assert "HD004" in ids(lint(tmp_path, deploy("staging", False, rollback=False)))
    assert "HD004" not in ids(lint(tmp_path, deploy("staging", False, rollback=True)))


def test_template_stage_is_linted(tmp_path):
    findings = lint(
        tmp_path,
        """
        template:
          type: Stage
          identifier: t
          spec:
            type: CI
            spec:
              caching: {enabled: true}
              execution:
                steps:
                  - step:
                      type: Run
                      identifier: r
                      spec:
                        command: make
        """,
    )
    assert ids(findings) == ["HD002"]


def test_inline_ignore(tmp_path):
    body = ci_step("command: make", timeout="").replace(
        "- step:", "# harness-doctor: ignore HD002\n                  - step:"
    )
    assert lint(tmp_path, body) == []


def test_select_and_ignore(tmp_path):
    body = ci_step("command: make\nprivileged: true", timeout="")
    assert set(ids(lint(tmp_path, body))) == {"HD002", "HD008"}
    assert ids(lint(tmp_path, body, select={"HD008"})) == ["HD008"]
    assert ids(lint(tmp_path, body, ignore={"HD008"})) == ["HD002"]


def test_examples():
    assert check_file(ROOT / "examples/good/deploy.yaml") == []
    found = {f.rule for f in check_file(ROOT / "examples/bad/deploy.yaml")}
    assert found == {"HD001", "HD002", "HD003", "HD004", "HD005", "HD006", "HD007", "HD009"}


def test_own_pipelines_are_clean():
    for path in (ROOT / ".harness").rglob("*.yaml"):
        assert check_file(path) == [], path


def test_exit_codes(capsys):
    assert main([str(ROOT / "examples/good")]) == 0
    assert main([str(ROOT / "examples/bad")]) == 1
    assert main([str(ROOT / "examples/bad"), "--fail-on", "never"]) == 0
    assert main([str(ROOT / "examples/bad"), "--select", "HD009"]) == 0
    assert main(["nope.yaml"]) == 2


def test_sarif_shape(capsys):
    main(["check", str(ROOT / "examples/bad"), "--format", "sarif", "--fail-on", "never"])
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"HD001", "HD009"}
    first = run["results"][0]
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_explain_and_rules(capsys):
    assert main(["explain", "hd005"]) == 0
    assert "approval" in capsys.readouterr().out.lower()
    assert main(["rules"]) == 0
    assert main(["explain", "HD999"]) == 2
