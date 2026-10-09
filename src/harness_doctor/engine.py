from __future__ import annotations

import re
from pathlib import Path

from .model import Doc, parse
from .rules import RULES, Finding

IGNORE = re.compile(r"#\s*harness-doctor:\s*ignore\s+([A-Z0-9, ]+)")


def _suppressed(doc: Doc, rule_id: str, line: int) -> bool:
    # a comment on the finding's line, or on either of the two lines above it
    for n in range(max(1, line - 2), line + 1):
        if n <= len(doc.lines):
            m = IGNORE.search(doc.lines[n - 1])
            if m and rule_id in re.split(r"[, ]+", m.group(1).strip()):
                return True
    return False


def check_file(path: Path, select: set[str] | None = None, ignore: set[str] | None = None) -> list[Finding]:
    doc = parse(path)
    found: list[Finding] = []
    for rule in RULES.values():
        if (select and rule.id not in select) or (ignore and rule.id in ignore):
            continue
        for line, message, hint in rule.check(doc):
            if not _suppressed(doc, rule.id, line):
                found.append(Finding(rule.id, rule.severity, message, str(path), line, hint))
    return sorted(set(found), key=lambda f: (f.file, f.line, f.rule))
