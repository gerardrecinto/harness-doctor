import pytest

from harness_doctor import schema
from harness_doctor.cli import main

TINY = {
    "type": "object",
    "required": ["pipeline"],
    "properties": {
        "pipeline": {
            "type": "object",
            "required": ["identifier", "stages"],
            "properties": {"stages": {"type": "array", "items": {"type": "object", "required": ["stage"]}}},
        }
    },
}


@pytest.fixture(autouse=True)
def tiny_schema(monkeypatch):
    monkeypatch.setattr(schema, "load_schema", lambda kind: TINY)


def test_valid_file(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("pipeline:\n  identifier: p\n  stages:\n    - stage: {}\n")
    assert schema.validate_file(f) == []


def test_error_points_at_the_offending_line(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("pipeline:\n  identifier: p\n  stages:\n    - stage: {}\n    - bogus: 1\n")
    (finding,) = schema.validate_file(f)
    assert finding.rule == "SCHEMA" and finding.line == 5
    assert "stage" in finding.message


def test_unknown_kinds_are_skipped(tmp_path):
    f = tmp_path / "svc.yaml"
    f.write_text("service:\n  name: x\n")
    assert schema.validate_file(f) == []


def test_cli_schema_exit_codes(tmp_path):
    ok, bad = tmp_path / "ok.yaml", tmp_path / "bad.yaml"
    ok.write_text("pipeline:\n  identifier: p\n  stages: []\n")
    bad.write_text("pipeline:\n  stages: []\n")
    assert main(["schema", str(ok)]) == 0
    assert main(["schema", str(bad)]) == 1
