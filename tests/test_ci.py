"""GitHub Actions (GA) and Jenkins (JK) rules."""

import json
import textwrap
from pathlib import Path

import pytest

from harness_doctor.cli import main
from harness_doctor.engine import check_file
from harness_doctor.model import discover, parse

ROOT = Path(__file__).resolve().parent.parent


def workflow(tmp_path, body: str, **kw):
    f = tmp_path / "wf.yml"
    f.write_text(textwrap.dedent(body))
    return check_file(f, **kw)


def jenkins(tmp_path, body: str, **kw):
    f = tmp_path / "Jenkinsfile"
    f.write_text(textwrap.dedent(body))
    return check_file(f, **kw)


def ids(findings):
    return sorted(f.rule for f in findings)


CLEAN_WORKFLOW = """
    name: ci
    on: [push]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        timeout-minutes: 10
        steps:
          - uses: actions/checkout@v4
          - run: make test
    """


# --- routing -----------------------------------------------------------------


def test_clean_workflow_has_no_findings(tmp_path):
    assert workflow(tmp_path, CLEAN_WORKFLOW) == []


def test_workflow_is_detected_even_though_yaml_reads_on_as_true(tmp_path):
    f = tmp_path / "wf.yml"
    f.write_text(textwrap.dedent(CLEAN_WORKFLOW))
    assert parse(f).flavor == "github"


def test_a_harness_file_is_not_read_as_a_workflow(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("pipeline:\n  identifier: p\n  stages: []\n")
    assert parse(f).flavor == "harness"


def test_jenkinsfile_names_are_recognised(tmp_path):
    for name in ("Jenkinsfile", "Jenkinsfile.release", "build.jenkinsfile"):
        f = tmp_path / name
        f.write_text("pipeline { agent { label 'x' } }\n")
        assert parse(f).flavor == "jenkins"


def test_discover_finds_jenkinsfiles_and_yaml(tmp_path):
    (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / "a.yml").write_text("name: x\n")
    (tmp_path / "notes.txt").write_text("ignore me\n")
    names = sorted(p.name for p in discover([str(tmp_path)]))
    assert names == ["Jenkinsfile", "a.yml"]


# --- GA001 -------------------------------------------------------------------


def test_ga001_flags_a_third_party_tag(tmp_path):
    found = workflow(tmp_path, CLEAN_WORKFLOW.replace("make test", "make test\n          - uses: acme/deploy@v2"))
    assert ids(found) == ["GA001"]



def test_ga001_accepts_a_full_sha_first_party_local_and_docker(tmp_path):
    sha = "a" * 40
    body = f"""
    on: [push]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        timeout-minutes: 5
        steps:
          - uses: acme/deploy@{sha}
          - uses: actions/setup-python@v5
          - uses: github/codeql-action/analyze@v3
          - uses: ./local-action
          - uses: docker://alpine:3.20
    """
    assert workflow(tmp_path, body) == []


# --- GA002 / GA005 -----------------------------------------------------------


def test_ga002_when_no_permissions_anywhere(tmp_path):
    body = CLEAN_WORKFLOW.replace("permissions:\n      contents: read\n    ", "")
    assert "GA002" in ids(workflow(tmp_path, body))



def test_ga002_not_raised_when_every_job_sets_permissions(tmp_path):
    body = """
    on: [push]
    jobs:
      test:
        runs-on: ubuntu-latest
        timeout-minutes: 5
        permissions:
          contents: read
        steps:
          - run: make test
    """
    assert workflow(tmp_path, body) == []


def test_ga005_write_all_at_workflow_and_job_level(tmp_path):
    top = CLEAN_WORKFLOW.replace("permissions:\n      contents: read", "permissions: write-all")
    assert "GA005" in ids(workflow(tmp_path, top))
    job = CLEAN_WORKFLOW.replace("runs-on: ubuntu-latest", "runs-on: ubuntu-latest\n        permissions: write-all")
    assert "GA005" in ids(workflow(tmp_path, job))


# --- GA003 / GA006 / GA009 ---------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.pull_request.title",
        "github.event.issue.body",
        "github.head_ref",
        "github.event.head_commit.message",
        "github.event.comment.body",
    ],
)
def test_ga003_flags_untrusted_context_in_run(tmp_path, expression):
    body = CLEAN_WORKFLOW.replace("make test", f"echo ${{{{ {expression} }}}}")
    found = workflow(tmp_path, body)
    assert "GA003" in ids(found)
    assert "}}" in [f for f in found if f.rule == "GA003"][0].message



def test_ga003_flags_github_script(tmp_path):
    body = """
    on: [pull_request]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        timeout-minutes: 5
        steps:
          - uses: actions/github-script@v7
            with:
              script: |
                console.log("${{ github.event.pull_request.title }}")
    """
    assert ids(workflow(tmp_path, body)) == ["GA003"]


def test_ga003_ignores_safe_context_and_env_indirection(tmp_path):
    body = CLEAN_WORKFLOW.replace(
        "- run: make test",
        "- env:\n              TITLE: ${{ github.event.pull_request.title }}\n            run: echo \"$TITLE\" ${{ github.sha }}",
    )
    assert "GA003" not in ids(workflow(tmp_path, body))


def test_ga006_secret_in_script(tmp_path):
    body = CLEAN_WORKFLOW.replace("make test", "./deploy ${{ secrets.TOKEN }}")
    assert "GA006" in ids(workflow(tmp_path, body))


def test_ga009_pipe_to_shell(tmp_path):
    body = CLEAN_WORKFLOW.replace("make test", "curl -sL https://example.com/i.sh | sh")
    assert "GA009" in ids(workflow(tmp_path, body))


# --- GA004 / GA007 / GA008 ---------------------------------------------------


def test_ga004_pull_request_target_checkout_of_pr_head(tmp_path):
    body = CLEAN_WORKFLOW.replace("on: [push]", "on:\n      pull_request_target:").replace(
        "- uses: actions/checkout@v4",
        "- uses: actions/checkout@v4\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}",
    )
    assert "GA004" in ids(workflow(tmp_path, body))


def test_ga004_not_raised_for_plain_pull_request_or_base_checkout(tmp_path):
    pr = CLEAN_WORKFLOW.replace("on: [push]", "on: [pull_request]").replace(
        "- uses: actions/checkout@v4",
        "- uses: actions/checkout@v4\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}",
    )
    assert "GA004" not in ids(workflow(tmp_path, pr))
    target = CLEAN_WORKFLOW.replace("on: [push]", "on: [pull_request_target]")
    assert "GA004" not in ids(workflow(tmp_path, target))


def test_ga007_self_hosted_on_pull_request(tmp_path):
    body = CLEAN_WORKFLOW.replace("on: [push]", "on: [pull_request]").replace("ubuntu-latest", "[self-hosted, linux]")
    assert "GA007" in ids(workflow(tmp_path, body))
    push_only = CLEAN_WORKFLOW.replace("ubuntu-latest", "[self-hosted, linux]")
    assert "GA007" not in ids(workflow(tmp_path, push_only))



def test_ga008_missing_timeout_is_info(tmp_path):
    body = CLEAN_WORKFLOW.replace("timeout-minutes: 10\n        ", "")
    assert [(f.rule, f.severity) for f in workflow(tmp_path, body)] == [("GA008", "info")]


def test_ga008_skips_jobs_that_call_a_reusable_workflow(tmp_path):
    body = """
    on: [push]
    permissions:
      contents: read
    jobs:
      call:
        uses: ./.github/workflows/other.yml
    """
    assert workflow(tmp_path, body) == []


# --- Jenkins -----------------------------------------------------------------

CLEAN_JENKINS = """
    pipeline {
        agent { label 'linux' }
        options { timeout(time: 30, unit: 'MINUTES') }
        stages {
            stage('Build') {
                steps { sh 'make build' }
            }
        }
    }
    """


def test_clean_jenkinsfile_has_no_findings(tmp_path):
    assert jenkins(tmp_path, CLEAN_JENKINS) == []


def test_jk001_literal_credential_but_not_credentials_helper(tmp_path):
    bad = jenkins(tmp_path, CLEAN_JENKINS.replace("agent { label 'linux' }", "agent { label 'linux' }\n    environment { DB_PASSWORD = 'hunter2hunter2' }"))
    assert "JK001" in ids(bad)
    good = jenkins(tmp_path, CLEAN_JENKINS.replace("agent { label 'linux' }", "agent { label 'linux' }\n    environment { DB_PASSWORD = credentials('db') }"))
    assert "JK001" not in ids(good)


def test_jk001_known_token_shape(tmp_path):
    key = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key, split so scanners do not flag this file
    body = CLEAN_JENKINS.replace("make build", f"curl -H 'x: {key}' h")
    assert "JK001" in ids(jenkins(tmp_path, body))


def test_jk002_agent_any(tmp_path):
    assert "JK002" in ids(jenkins(tmp_path, CLEAN_JENKINS.replace("agent { label 'linux' }", "agent any")))


def test_jk003_no_timeout(tmp_path):
    body = CLEAN_JENKINS.replace("options { timeout(time: 30, unit: 'MINUTES') }\n    ", "")
    assert "JK003" in ids(jenkins(tmp_path, body))
    assert "JK003" not in ids(jenkins(tmp_path, CLEAN_JENKINS))


def test_jk004_double_quoted_sh_with_branch_or_param(tmp_path):
    for expr in ("${params.TARGET}", "${env.BRANCH_NAME}", "$CHANGE_TITLE"):
        body = CLEAN_JENKINS.replace("sh 'make build'", f'sh "make build {expr}"')
        assert "JK004" in ids(jenkins(tmp_path, body)), expr


def test_jk004_triple_quoted_block(tmp_path):
    body = CLEAN_JENKINS.replace("sh 'make build'", 'sh """\n                make build\n                echo ${env.BRANCH_NAME}\n                """')
    assert "JK004" in ids(jenkins(tmp_path, body))


def test_jk004_not_raised_for_single_quotes_or_safe_values(tmp_path):
    safe = CLEAN_JENKINS.replace("sh 'make build'", "sh 'echo $BRANCH_NAME'")
    assert "JK004" not in ids(jenkins(tmp_path, safe))
    other = CLEAN_JENKINS.replace("sh 'make build'", 'sh "make build ${env.BUILD_NUMBER}"')
    assert "JK004" not in ids(jenkins(tmp_path, other))


@pytest.mark.parametrize("image", ["node", "node:latest", "registry.example.com/team/app"])
def test_jk005_unpinned_image(tmp_path, image):
    body = CLEAN_JENKINS.replace("agent { label 'linux' }", f"agent {{ docker {{ image '{image}' }} }}")
    assert "JK005" in ids(jenkins(tmp_path, body))


@pytest.mark.parametrize("image", ["node:20.11", "registry.example.com:5000/app:1.2", f"app@sha256:{'b' * 64}", "${IMAGE}"])
def test_jk005_accepts_pinned_images(tmp_path, image):
    body = CLEAN_JENKINS.replace("agent { label 'linux' }", f"agent {{ docker {{ image '{image}' }} }}")
    assert "JK005" not in ids(jenkins(tmp_path, body))


def test_jk006_prod_deploy_needs_an_approval_first(tmp_path):
    body = CLEAN_JENKINS.replace(
        "stage('Build') {",
        "stage('Deploy to production') {",
    )
    assert "JK006" in ids(jenkins(tmp_path, body))


def test_jk006_approval_before_or_inside_the_stage_satisfies_it(tmp_path):
    before = CLEAN_JENKINS.replace(
        "stage('Build') {\n                steps { sh 'make build' }\n            }",
        "stage('Approve') {\n                steps { input message: 'Ship it?' }\n            }\n            stage('Deploy to prod') {\n                steps { sh './deploy' }\n            }",
    )
    assert "JK006" not in ids(jenkins(tmp_path, before))
    inside = CLEAN_JENKINS.replace(
        "stage('Build') {\n                steps { sh 'make build' }",
        "stage('Release to prod') {\n                steps {\n                    input(message: 'Ship it?')\n                    sh './deploy'\n                }",
    )
    assert "JK006" not in ids(jenkins(tmp_path, inside))


def test_jk006_ignores_non_production_deploys(tmp_path):
    body = CLEAN_JENKINS.replace("stage('Build') {", "stage('Deploy to staging') {")
    assert "JK006" not in ids(jenkins(tmp_path, body))


def test_jk007_pipe_to_shell(tmp_path):
    body = CLEAN_JENKINS.replace("make build", "curl -s https://example.com/x.sh | bash")
    assert "JK007" in ids(jenkins(tmp_path, body))


def test_comments_are_not_scanned_and_urls_survive_comment_stripping(tmp_path):
    body = CLEAN_JENKINS.replace("agent { label 'linux' }", "// agent any\n    agent { label 'linux' }")
    assert jenkins(tmp_path, body) == []
    url = CLEAN_JENKINS.replace("make build", "curl -fsSLo x.tgz https://example.com/x.tgz")
    assert jenkins(tmp_path, url) == []


def test_jenkins_suppression_comment(tmp_path):
    body = CLEAN_JENKINS.replace("agent { label 'linux' }", "// harness-doctor: ignore JK002\n    agent any")
    assert "JK002" not in ids(jenkins(tmp_path, body))


# --- CLI and examples --------------------------------------------------------


def test_examples_trigger_the_expected_rules():
    wf = {f.rule for f in check_file(ROOT / "examples/bad/workflow.yml")}
    assert wf == {"GA001", "GA003", "GA004", "GA005", "GA006", "GA007", "GA008", "GA009"}
    jk = {f.rule for f in check_file(ROOT / "examples/bad/Jenkinsfile")}
    assert jk == {"JK001", "JK002", "JK003", "JK004", "JK005", "JK006", "JK007"}
    assert check_file(ROOT / "examples/good/workflow.yml") == []
    assert check_file(ROOT / "examples/good/Jenkinsfile") == []


def test_select_and_ignore_work_across_kinds(tmp_path):
    found = check_file(ROOT / "examples/bad/workflow.yml", select={"GA003"})
    assert ids(found) == ["GA003"]
    found = check_file(ROOT / "examples/bad/Jenkinsfile", ignore={"JK001", "JK006"})
    assert "JK001" not in ids(found) and "JK006" not in ids(found)


def test_cli_checks_a_mixed_directory_and_lists_rule_kinds(capsys):
    assert main([str(ROOT / "examples/bad"), "--fail-on", "never", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {"HD001", "GA003", "JK006"} <= {f["rule"] for f in data["findings"]}
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "github" in out and "jenkins" in out and "harness" in out


def test_cli_explains_a_new_rule(capsys):
    assert main(["explain", "ga004"]) == 0
    assert "pull_request_target" in capsys.readouterr().out


def test_schema_command_skips_non_harness_files(capsys):
    pytest.importorskip("jsonschema")
    assert main(["schema", str(ROOT / "examples/good/workflow.yml"), str(ROOT / "examples/good/Jenkinsfile")]) == 0
    assert "no findings" in capsys.readouterr().out


def test_sarif_lists_the_new_rules(capsys):
    main(["check", str(ROOT / "examples/bad/workflow.yml"), "--format", "sarif", "--fail-on", "never"])
    sarif = json.loads(capsys.readouterr().out)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"GA001", "JK006", "HD001"} <= rule_ids
