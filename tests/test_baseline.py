import json
import shutil
from pathlib import Path

from harness_doctor.cli import main

ROOT = Path(__file__).resolve().parent.parent
BAD = ROOT / "examples" / "bad" / "deploy.yaml"


def run(capsys, *args):
    code = main(list(args))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_baseline_hides_existing_and_fails_on_new(tmp_path, capsys):
    d = tmp_path / "pipes"
    d.mkdir()
    shutil.copy(BAD, d / "deploy.yaml")
    base = tmp_path / "base.json"
    code, out, _ = run(capsys, "check", str(d), "--write-baseline", str(base))
    assert code == 0 and "saved" in out

    code, out, err = run(capsys, "check", str(d), "--baseline", str(base))
    assert code == 0 and "no findings" in out and "covered" in err

    # lines shifting does not matter; a pipeline added later is new and fails
    (d / "deploy.yaml").write_text("# one more line above\n" + BAD.read_text())
    shutil.copy(BAD, d / "second.yaml")
    code, out, _ = run(capsys, "check", str(d), "--baseline", str(base), "--format", "json")
    assert code == 1
    assert {f["file"] for f in json.loads(out)["findings"]} == {str(d / "second.yaml")}


def test_baseline_reports_fixed_entries_and_bad_files(tmp_path, capsys):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"version": 1, "findings": [{"rule": "HD001", "file": "gone.yaml", "message": "x", "count": 2}]}))
    code, _, err = run(capsys, "check", str(ROOT / "examples" / "good"), "--baseline", str(base))
    assert code == 0 and "2 baseline entries no longer occur" in err

    code, _, err = run(capsys, "check", str(BAD), "--baseline", str(tmp_path / "missing.json"))
    assert code == 2 and "--write-baseline" in err
    (tmp_path / "junk.json").write_text("nope")
    code, _, err = run(capsys, "check", str(BAD), "--baseline", str(tmp_path / "junk.json"))
    assert code == 2 and "not a harness-doctor baseline" in err
