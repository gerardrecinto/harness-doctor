"""Verify executable workflow pins and the actual gitleaks shell failure paths."""
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"


def test_executable_actions_are_pinned():
    paths = [*ROOT.glob(".github/workflows/*.yml"), ROOT / "action.yml"]
    refs = []
    for path in paths:
        for ref in re.findall(r"\buses:\s*([^\s#]+)", path.read_text()):
            if ref.startswith("./"):
                continue
            refs.append(ref)
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), (path, ref)
    assert refs, "no executable action references checked"


@pytest.mark.parametrize("download", ["valid", "tampered", "missing", "error"])
def test_gitleaks_download_is_verified_before_execution(tmp_path, download):
    workflow = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
    steps = workflow["jobs"]["secrets"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Run gitleaks")
    assert GITLEAKS_SHA256 in script, "review the pinned official release digest when upgrading"
    payload = b"test archive fixture"
    digest = hashlib.sha256(payload).hexdigest()
    # Exercise the exact workflow shell, replacing only the archive digest so a
    # tiny local fixture can cover both acceptance and rejection without a download.
    script = script.replace(GITLEAKS_SHA256, digest)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    archive = tmp_path / "gitleaks_8.30.1_linux_x64.tar.gz"
    if download in {"valid", "tampered"}:
        archive.write_bytes(payload if download == "valid" else payload + b"corrupted")
    stubs = {
        "curl": "exit 7" if download == "error" else "exit 0",
        "tar": 'echo extracted >> "$TRACE"',
        "gitleaks": 'echo executed >> "$TRACE"',
    }
    for name, body in stubs.items():
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\n" + body + "\n")
        executable.chmod(0o755)
    trace = tmp_path / "trace"
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=tmp_path, env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "TRACE": str(trace)},
        text=True, capture_output=True, timeout=10,
    )
    if download == "valid":
        assert result.returncode == 0, result.stderr
        assert trace.read_text().splitlines() == ["extracted", "executed"]
    else:
        assert result.returncode != 0, result.stdout
        assert not trace.exists(), "unverified archive reached extraction or execution"
