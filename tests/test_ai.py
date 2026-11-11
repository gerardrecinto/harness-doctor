"""AI workload delivery rules (AI001 to AI004)."""

import json
import textwrap
from pathlib import Path

import pytest

from harness_doctor.engine import check_file

ROOT = Path(__file__).resolve().parent.parent
SHA = "0e9e39f249a16976918f6564b8830bc894c89659"


def workflow(tmp_path, steps: str):
    f = tmp_path / "wf.yml"
    f.write_text(
        "name: x\non: [push]\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 10\n    steps:\n" + textwrap.indent(textwrap.dedent(steps), "      ")
    )
    return sorted(x.rule for x in check_file(f))


@pytest.mark.parametrize(
    "cmd",
    [
        "huggingface-cli download org/model",
        "huggingface-cli download org/model --revision main",
        "python -c 'from huggingface_hub import snapshot_download; snapshot_download(\"org/m\")'",
        "git clone https://huggingface.co/org/model",
    ],
)
def test_unpinned_model_pull_is_flagged(tmp_path, cmd):
    assert "AI001" in workflow(tmp_path, f"- run: {json.dumps(cmd)}\n")


@pytest.mark.parametrize(
    "cmd",
    [
        f"huggingface-cli download org/model --revision {SHA}",
        f"python -c 'snapshot_download(\"org/m\", revision=\"{SHA}\")'",
        "make test",
    ],
)
def test_pinned_or_unrelated_commands_are_not_flagged(tmp_path, cmd):
    assert "AI001" not in workflow(tmp_path, f"- run: {json.dumps(cmd)}\n")


def test_second_model_pull_on_a_later_line_is_still_checked(tmp_path):
    body = f"- run: |\n    huggingface-cli download a/b --revision {SHA}\n    huggingface-cli download c/d\n"
    assert "AI001" in workflow(tmp_path, body)


def test_push_needs_scan_and_sbom(tmp_path):
    assert {"AI002", "AI003"} <= set(workflow(tmp_path, "- run: docker push r.io/a:1\n"))
    scanned = "- run: trivy image r.io/a:1\n- run: docker push r.io/a:1\n"
    got = workflow(tmp_path, scanned)
    assert "AI002" not in got and "AI003" in got
    full = scanned + "- run: syft r.io/a:1 -o cyclonedx-json\n"
    got = workflow(tmp_path, full)
    assert "AI002" not in got and "AI003" not in got


def test_build_push_action_with_push_true_counts_as_a_push(tmp_path):
    body = "- uses: docker/build-push-action@v6\n  with:\n    push: true\n    tags: r.io/a:1\n"
    assert "AI002" in workflow(tmp_path, body)
    sbom = "- uses: docker/build-push-action@v6\n  with:\n    push: true\n    sbom: true\n"
    assert "AI003" not in workflow(tmp_path, sbom)
    no_push = "- uses: docker/build-push-action@v6\n  with:\n    push: false\n"
    assert not {"AI002", "AI003"} & set(workflow(tmp_path, no_push))


def test_deploy_needs_a_wait_or_rollback(tmp_path):
    assert "AI004" in workflow(tmp_path, "- run: helm upgrade app ./chart\n")
    assert "AI004" not in workflow(tmp_path, "- run: helm upgrade app ./chart --atomic --wait\n")
    both = "- run: kubectl apply -f k8s/\n- run: kubectl rollout status deploy/app --timeout=10m\n"
    assert "AI004" not in workflow(tmp_path, both)


def test_the_ai_examples_behave():
    bad = {f.rule for f in check_file(ROOT / "examples/bad/ai-release.yml")}
    assert bad == {"AI001", "AI002", "AI003", "AI004"}
    assert check_file(ROOT / "examples/good/ai-release.yml") == []


def test_suppression_comment_works(tmp_path):
    f = tmp_path / "wf.yml"
    f.write_text(
        "name: x\non: [push]\npermissions:\n  contents: read\njobs:\n  # harness-doctor: ignore AI004\n  j:\n    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 10\n    steps:\n      - run: helm upgrade app ./chart\n"
    )
    assert "AI004" not in {x.rule for x in check_file(f)}
