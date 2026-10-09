"""Validate pipelines, templates and triggers against Harness's published JSON schema."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from .model import Node, parse
from .rules import ERROR, Finding

BASE = "https://raw.githubusercontent.com/harness/harness-schema/main/v0/{}.json"
KINDS = {"pipeline", "template", "trigger"}


def _cache_dir() -> Path:
    root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(root) / "harness-doctor"


def load_schema(kind: str) -> dict:
    cached = _cache_dir() / f"{kind}.json"
    if not cached.exists():
        cached.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(BASE.format(kind), timeout=60) as resp:
            cached.write_bytes(resp.read())
    return json.loads(cached.read_text())


def _line_at(root: Node, path) -> int:
    cur, line = root, root.line
    for part in path:
        try:
            cur = cur[part]
        except (KeyError, IndexError, TypeError):
            break
        line = getattr(cur, "line", line)
    return line


def _most_specific(error):
    """A oneOf over stage types buries the real problem. Prefer the branch that got furthest."""
    while error.context:
        branches = [
            c for c in error.context
            if not (c.validator == "enum" and list(c.absolute_path)[-1:] == ["type"])
        ]
        if not branches:
            break
        error = max(branches, key=lambda c: len(c.absolute_path))
    return error


def validate_file(path: Path) -> list[Finding]:
    try:
        import jsonschema
        from jsonschema.exceptions import best_match
    except ImportError as exc:
        raise SystemExit("schema checks need jsonschema: pip install 'harness-doctor[schema]'") from exc

    doc = parse(path)
    kind = doc.kind
    if kind not in KINDS:
        return []
    schema = load_schema(kind)
    validator = jsonschema.validators.validator_for(schema)(schema)
    error = best_match(validator.iter_errors(json.loads(json.dumps(doc.root))))
    if error is None:
        return []
    error = _most_specific(error)
    where = "/".join(str(p) for p in error.absolute_path) or kind
    return [
        Finding(
            "SCHEMA",
            ERROR,
            f"{error.message[:140]} (at {where})",
            str(path),
            _line_at(doc.root, error.absolute_path),
            "compare against https://github.com/harness/harness-schema",
        )
    ]
