"""Run the documented install from a fresh directory, outside the source tree."""
import html
import os
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
readme = (root / "README.md").read_text()
commands = readme.split("```", 2)[1].strip()
site = (root / "site/index.html").read_text().split('id="install"', 1)[1]
site_commands = html.unescape(re.search(r"<pre[^>]*><code>(.*?)</code></pre>", site, re.S)[1]).strip()
assert site_commands == commands, "site and README install instructions diverged"
url = "https://github.com/gerardrecinto/harness-doctor"
assert commands.count(url) == 1, "README quick start needs one clone command"
# Test this PR's tree, not a different revision fetched from main.
commands = commands.replace(url, '"' + str(root) + '"')
# A local clone only sees committed changes; build the checkout's documentation
# with the CLI source at the same commit in CI.
with tempfile.TemporaryDirectory(prefix="harness-quickstart-") as directory:
    result = subprocess.run(
        ["bash", "-eu", "-c", commands], cwd=directory,
        text=True, capture_output=True, timeout=300,
        env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
    )
    print(result.stdout)
    print(result.stderr)
    assert result.returncode == 1, f"expected findings exit 1, got {result.returncode}"
    assert "2 errors, 5 warnings, 1 info in 1 file" in result.stdout
    cli = Path(directory) / "harness-doctor/.venv/bin/harness-doctor"
    clean = subprocess.run(
        [str(cli), "check", "examples/good"],
        cwd=cli.parents[2], text=True, capture_output=True, timeout=30,
    )
    print(clean.stdout)
    print(clean.stderr)
    assert clean.returncode == 0, "installed CLI rejected the documented clean samples"
    assert "no findings" in clean.stdout
