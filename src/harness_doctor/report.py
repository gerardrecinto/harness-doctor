from __future__ import annotations

import json
from collections import Counter
from itertools import groupby
from pathlib import PurePath

from . import __version__
from .rules import RULES, Finding

SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note"}


def as_text(findings: list[Finding], files: int) -> str:
    out: list[str] = []
    for file, group in groupby(findings, key=lambda f: f.file):
        out.append(file)
        for f in group:
            out.append(f"  {f.line:>4}  {f.severity:<7}  {f.rule}  {f.message}")
            if f.hint:
                out.append(f"                         fix: {f.hint}")
        out.append("")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}{'s' if counts[s] != 1 else ''}" for s in ("error", "warning", "info") if counts[s])
    out.append(f"{summary or 'no findings'} in {files} file{'s' if files != 1 else ''}")
    return "\n".join(out)


def as_json(findings: list[Finding], files: int) -> str:
    return json.dumps(
        {
            "version": __version__,
            "files": files,
            "findings": [f.__dict__ for f in findings],
        },
        indent=2,
    )


def as_sarif(findings: list[Finding], files: int) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.why},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        }
        for r in RULES.values()
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message + (f". Fix: {f.hint}" if f.hint else "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": PurePath(f.file).as_posix()},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "harness-doctor",
                        "version": __version__,
                        "informationUri": "https://github.com/gerardrecinto/harness-doctor",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def as_github(findings: list[Finding], files: int) -> str:
    """Workflow commands: GitHub shows these as inline annotations on the PR diff."""
    level = {"error": "error", "warning": "warning", "info": "notice"}
    lines = []
    for f in findings:
        text = f.message + (f". Fix: {f.hint}" if f.hint else "")
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        lines.append(f"::{level[f.severity]} file={f.file},line={f.line},title={f.rule}::{text}")
    return "\n".join(lines)


FORMATS = {"text": as_text, "json": as_json, "sarif": as_sarif, "github": as_github}
