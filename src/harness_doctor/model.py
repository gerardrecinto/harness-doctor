"""Load Harness YAML with line numbers and index its stages and steps."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class Node(dict):
    """A YAML mapping that remembers the line it started on."""

    line: int = 1


class _Loader(yaml.SafeLoader):
    pass


def _construct_map(loader: _Loader, node: yaml.MappingNode) -> Node:
    mapping = Node(loader.construct_mapping(node, deep=True))
    mapping.line = node.start_mark.line + 1
    return mapping


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_map)


@dataclass
class Doc:
    path: Path
    root: Node
    lines: list[str]
    stages: list[Node] = field(default_factory=list)
    steps: list[tuple[Node, Node | None]] = field(default_factory=list)
    # "harness" (default), "github" for an Actions workflow, "jenkins" for a Jenkinsfile
    flavor: str = "harness"

    @property
    def kind(self) -> str | None:
        for key in ("pipeline", "template", "trigger", "inputSet"):
            if key in self.root:
                return key
        return None


def _walk(node, stage, doc: Doc) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "stage" and isinstance(value, dict):
                doc.stages.append(value)
                _walk(value, value, doc)
            elif key == "step" and isinstance(value, dict):
                doc.steps.append((value, stage))
                _walk(value, stage, doc)
            else:
                _walk(value, stage, doc)
    elif isinstance(node, list):
        for item in node:
            _walk(item, stage, doc)


JENKINSFILE = re.compile(r"^Jenkinsfile|\.jenkinsfile$", re.IGNORECASE)


def is_jenkinsfile(path: Path) -> bool:
    return bool(JENKINSFILE.search(path.name))


def _is_workflow(root: Node) -> bool:
    # YAML 1.1 reads the key `on` as the boolean True, so accept both spellings
    return "jobs" in root and ("on" in root or True in root)


def parse(path: Path) -> Doc:
    text = path.read_text(encoding="utf-8")
    if is_jenkinsfile(path):
        return Doc(path=path, root=Node(), lines=text.splitlines(), flavor="jenkins")
    root = yaml.load(text, Loader=_Loader)
    if not isinstance(root, Node):
        raise ValueError("top level is not a mapping")
    if _is_workflow(root):
        return Doc(path=path, root=root, lines=text.splitlines(), flavor="github")
    doc = Doc(path=path, root=root, lines=text.splitlines())
    template = root.get("template")
    if isinstance(template, dict) and isinstance(template.get("spec"), dict):
        spec = template["spec"]
        if template.get("type") == "Stage":
            doc.stages.append(spec)
            _walk(spec, spec, doc)
        elif template.get("type") == "Step":
            doc.steps.append((spec, None))
            _walk(spec, None, doc)
        else:
            _walk(spec, None, doc)
    else:
        _walk(root, None, doc)
    return doc


def discover(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found += sorted(
                x for x in p.rglob("*") if x.suffix in (".yaml", ".yml") or (x.is_file() and is_jenkinsfile(x))
            )
        elif p.is_file():
            found.append(p)
        else:
            raise FileNotFoundError(raw)
    return found
