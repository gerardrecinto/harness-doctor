"""Adopt the linter on pipelines that already have findings: record them once, fail only on new ones."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .rules import Finding


def _key(f: Finding) -> tuple[str, str, str]:
    # The line is left out on purpose: it moves whenever someone edits above it.
    return (f.rule, Path(f.file).as_posix(), f.message)


def write(path: str, findings: list[Finding]) -> None:
    counts = Counter(_key(f) for f in findings)
    rows = [{"rule": r, "file": fl, "message": m, "count": n} for (r, fl, m), n in sorted(counts.items())]
    Path(path).write_text(json.dumps({"version": 1, "findings": rows}, indent=2) + "\n")


def load(path: str) -> Counter:
    try:
        data = json.loads(Path(path).read_text())
        return Counter({(r["rule"], r["file"], r["message"]): int(r["count"]) for r in data["findings"]})
    except FileNotFoundError:
        raise ValueError(f"{path} does not exist. Create it with: harness-doctor check PATH --write-baseline {path}") from None
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError(f"{path} is not a harness-doctor baseline. Recreate it with --write-baseline {path}") from None


def apply(findings: list[Finding], known: Counter) -> tuple[list[Finding], int, int]:
    """Return (new findings, how many the baseline covered, how many baseline entries no longer occur)."""
    left = Counter(known)
    new, covered = [], 0
    for f in findings:
        k = _key(f)
        if left[k] > 0:
            left[k] -= 1
            covered += 1
        else:
            new.append(f)
    return new, covered, sum(left.values())
