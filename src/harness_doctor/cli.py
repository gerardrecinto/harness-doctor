from __future__ import annotations

import argparse
import sys
import textwrap

import yaml

from . import __version__
from .engine import check_file
from .model import discover
from .report import FORMATS
from .rules import RULES, SEVERITY_RANK

COMMANDS = {"check", "schema", "rules", "explain"}


def _csv(value: str) -> set[str]:
    return {v.strip().upper() for v in value.split(",") if v.strip()}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harness-doctor",
        description="Lint Harness CI/CD pipeline YAML. 'harness-doctor PATH' is the same as 'harness-doctor check PATH'.",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_ in (("check", "run the lint rules"), ("schema", "validate against Harness's published JSON schema")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("paths", nargs="+", help="files or directories (.yaml/.yml)")
        s.add_argument("--format", choices=sorted(FORMATS), default="text")
        s.add_argument("--fail-on", choices=["error", "warning", "info", "never"], default="error")
        if name == "check":
            s.add_argument("--select", type=_csv, help="only these rule ids, comma separated")
            s.add_argument("--ignore", type=_csv, help="skip these rule ids, comma separated")

    sub.add_parser("rules", help="list every rule")
    e = sub.add_parser("explain", help="say why a rule exists")
    e.add_argument("rule")
    return p


def _run(args: argparse.Namespace) -> int:
    try:
        files = discover(args.paths)
    except FileNotFoundError as exc:
        print(f"harness-doctor: no such path: {exc}", file=sys.stderr)
        return 2

    findings = []
    for path in files:
        try:
            if args.cmd == "schema":
                from .schema import validate_file

                findings += validate_file(path)
            else:
                findings += check_file(path, args.select, args.ignore)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            print(f"harness-doctor: {path}: {exc}", file=sys.stderr)
            return 2

    findings.sort(key=lambda f: (f.file, f.line, f.rule))
    print(FORMATS[args.format](findings, len(files)))
    if args.fail_on == "never":
        return 0
    bar = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] >= bar for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "check")
    args = _parser().parse_args(argv)

    if args.cmd == "rules":
        for r in RULES.values():
            print(f"{r.id}  {r.severity:<7}  {r.title}")
        return 0
    if args.cmd == "explain":
        r = RULES.get(args.rule.upper())
        if not r:
            print(f"harness-doctor: unknown rule {args.rule}", file=sys.stderr)
            return 2
        print(f"{r.id} ({r.severity}): {r.title}\n")
        print(textwrap.fill(r.why, 88))
        return 0
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
