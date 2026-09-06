#!/usr/bin/env python3
"""Reject explicit tool/model authorship credits in exact Git objects.

This is a deliberately lexical policy, not an authorship detector.  It catches
the repository's frozen identity, trailer, and credit grammars.  It does not
infer provenance or detect undisclosed assistance. Sentence-form product
discussion and Markdown vendor headings/lists remain outside the credit grammar.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_FINDINGS = 100
MAX_COMMITS = 10_000
MAX_STDIN_BYTES = 1024 * 1024
GIT_TIMEOUT_SECONDS = 10

_DASHES = str.maketrans({"‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-"})
_AI_ALIAS = re.compile(
    r"(?:ai assistant|anthropic|chatgpt|claude(?: code)?|codex|"
    r"(?:github )?copilot|gemini|gpt(?:[- ]?\d+(?:\.\d+)*)?|openai)"
)
_AI_IDENTITY = re.compile(
    rf"(?:the )?{_AI_ALIAS.pattern}(?: (?:agent|assistant|bot|model))?"
    rf"(?: \((?:anthropic|openai)\))?"
)
_AI_EMAIL = re.compile(
    r"(?:noreply@(anthropic\.com|openai\.com|claude\.ai)|"
    r"(?:chatgpt|claude|codex|copilot|gemini|gpt[-._]?\d*)"
    r"(?:[-._]?(?:agent|assistant|bot|noreply))?@"
    r"(?:anthropic\.com|openai\.com|claude\.ai))"
)
_IDENTITY_VALUE = re.compile(r"(?P<name>[^<>\r\n]+) <(?P<email>[^<>\s]+)>")
_BRACKET_LABEL = re.compile(r"\[(?P<label>[^\]\r\n]+)\]")
_ACTOR_SEPARATOR = re.compile(
    r"\s*(?:[,;]\s*(?:and\s+)?|&|\+|/|\band\b)\s*")
_MARKDOWN_ORDERED = re.compile(r"[0-9]{1,9}[.)][ \t]+")
_MARKDOWN_TASK = re.compile(r"\[[ xX]\][ \t]+")
_GIT_IDENTITY = re.compile(
    r"(?P<name>[^<>\r\n]+) <(?P<email>[^<>\s]+)> "
    r"(?P<epoch>-?\d+) (?P<offset>[+-]\d{4})"
)
_CREDIT = re.compile(
    r"(?:(?:this|the) (?:artifact|change|code|commit|document|implementation|"
    r"project|release|work) (?:is|was) )?"
    r"(?:authored by|built (?:by|using|with)|created (?:by|using|with)|"
    r"developed (?:by|using|with)|generated (?:by|using|with)|made with|"
    r"pair programmed with|produced (?:by|using|with)|written (?:by|with))"
    r"\s*:?[ \t]+(?P<actor>.+)"
)
_ROLE = re.compile(
    r"(?:senior )?(?:coding|development|research|writing) "
    r"(?:assistant|collaborator|contributor|partner)\s*:\s*(?P<actor>.+)"
)
_ARTIFACT_AI_CREDIT = re.compile(
    r"(?:this|the) (?:artifact|change|code|commit|document|implementation|"
    r"project|release|work) (?:is|was) "
    r"(?:ai[- ]assisted|ai[- ]generated|(?:created|generated|made) with ai)"
    r"[.!]?"
)
_TOOL_BYLINE = re.compile(
    rf"{_AI_ALIAS.pattern}\s*\((?:anthropic|openai)\)[.!]?"
)
_TRAILER_KEYS = frozenset({
    "assisted-by",
    "authored-by",
    "co-authored-by",
    "co-developed-by",
    "created-by",
    "created-using",
    "developed-by",
    "generated-by",
    "generated-with",
    "research-partner",
    "reviewed-by",
    "signed-off-by",
    "written-by",
    "written-with",
})


@dataclass(frozen=True, slots=True)
class Finding:
    source: str
    line: int
    code: str
    detail: str


class ScanIncomplete(RuntimeError):
    pass


def _normal(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).translate(_DASHES).casefold()
    return " ".join(value.split())


def _markdown_source(source: str) -> bool:
    return Path(source).suffix.casefold() in {
        ".adoc", ".md", ".markdown", ".rst", ".txt",
    }


def _undecorate(line: str, *, markdown: bool) -> tuple[str, bool]:
    value = line.strip()
    markup = False
    while value:
        if markdown:
            ordered = _MARKDOWN_ORDERED.match(value)
            if ordered is not None:
                markup = True
                value = value[ordered.end():]
                continue
            if markup:
                task = _MARKDOWN_TASK.match(value)
                if task is not None:
                    value = value[task.end():]
                    continue
        if markdown and value[0] in "#>*+-":
            markup = True
            value = value[1:].lstrip()
            continue
        if value.startswith("<!--"):
            value = value[4:].lstrip()
            continue
        if value.startswith("//"):
            value = value.lstrip("/").lstrip()
            if value.startswith("!"):
                value = value[1:].lstrip()
            continue
        if value.startswith(("/*", "--")):
            value = value[2:].lstrip()
            if value.startswith("!"):
                value = value[1:].lstrip()
            continue
        if value[0] in "#*;%":
            value = value[1:].lstrip()
            continue
        if unicodedata.category(value[0]) in {"Sk", "So"}:
            value = value[1:].lstrip(" \ufe0f")
            continue
        break
    if value.endswith("-->"):
        value = value[:-3].rstrip()
    elif value.endswith("*/"):
        value = value[:-2].rstrip()
    return _normal(value), markup


def _identity_reason(name: str, email: str) -> str | None:
    normalized_name = _normal(name)
    normalized_email = unicodedata.normalize("NFKC", email).casefold()
    if _AI_IDENTITY.fullmatch(normalized_name):
        return "tool/model authoring identity"
    if _AI_EMAIL.fullmatch(normalized_email):
        return "tool/model automation email"
    return None


def scan_identity(name: str, email: str, *, source: str) -> tuple[Finding, ...]:
    reason = _identity_reason(name, email)
    if reason is None:
        return ()
    return (Finding(source, 0, "attribution.identity", reason),)


def _single_actor_reason(value: str) -> str | None:
    value = value.strip(" \t.,;:!?*_`")
    parsed = _IDENTITY_VALUE.fullmatch(value)
    if parsed is not None:
        return _identity_reason(parsed["name"], parsed["email"])
    normalized = _normal(value)
    if _AI_IDENTITY.fullmatch(normalized):
        return "tool/model credited as author"
    return None


def _actor_reason(value: str) -> str | None:
    # Destinations and reference definitions do not change who a bracketed
    # label names. Inspect labels directly, then every nonempty plain actor;
    # prose outside a credit context never reaches this function.
    reason = _single_actor_reason(value)
    if reason is not None:
        return reason
    for match in _BRACKET_LABEL.finditer(value):
        reason = _single_actor_reason(match["label"])
        if reason is not None:
            return reason
    for actor in _ACTOR_SEPARATOR.split(value):
        if not actor.strip():
            continue
        reason = _single_actor_reason(actor)
        if reason is not None:
            return reason
    return None


def scan_prose(
        text: str, *, source: str, markdown: bool | None = None) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    if markdown is None:
        markdown = _markdown_source(source)
    for number, raw_line in enumerate(text.splitlines(), 1):
        line, markup = _undecorate(raw_line, markdown=markdown)
        if not line:
            continue
        reason = None
        key, separator, value = line.partition(":")
        if separator and key.replace("_", "-") in _TRAILER_KEYS:
            reason = _actor_reason(value)
        if reason is None:
            match = _CREDIT.fullmatch(line) or _ROLE.fullmatch(line)
            if match is not None:
                reason = _actor_reason(match["actor"])
        if reason is None and not markup and _TOOL_BYLINE.fullmatch(line):
            reason = "tool/model byline"
        if reason is None and _ARTIFACT_AI_CREDIT.fullmatch(line):
            reason = "explicit AI authorship statement"
        if reason is not None:
            findings.append(Finding(source, number, "attribution.credit", reason))
            if len(findings) >= MAX_FINDINGS:
                break
    return tuple(findings)


def _parse_git_identity(value: str, *, label: str) -> tuple[str, str]:
    match = _GIT_IDENTITY.fullmatch(value)
    if match is None:
        raise ScanIncomplete(f"{label} is not a canonical Git identity")
    return match["name"], match["email"]


def scan_commit_object(data: bytes, *, source: str) -> tuple[Finding, ...]:
    if b"\x00" in data:
        raise ScanIncomplete("commit object contains NUL")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanIncomplete("commit object is not valid UTF-8") from exc
    header_block, separator, message = text.partition("\n\n")
    if not separator:
        raise ScanIncomplete("commit object has no header/message boundary")
    authors = [line[7:] for line in header_block.splitlines() if line.startswith("author ")]
    committers = [
        line[10:] for line in header_block.splitlines() if line.startswith("committer ")
    ]
    if len(authors) != 1 or len(committers) != 1:
        raise ScanIncomplete("commit object must have one author and one committer")
    findings = list(scan_prose(message, source=source))
    for label, value in (("author", authors[0]), ("committer", committers[0])):
        name, email = _parse_git_identity(value, label=label)
        findings.extend(scan_identity(name, email, source=f"{source}:{label}"))
    return tuple(findings[:MAX_FINDINGS])


def _content_scanner():
    path = ROOT / ".github" / "scripts" / "check_content_marks.py"
    name = "causal_continuity_engine_attribution_content"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ScanIncomplete("cannot load exact-Git-object reader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _decode_blob(scanner, path: str, data: bytes) -> str | None:
    if b"\x00" in data:
        if scanner._looks_text_path(path):
            raise ScanIncomplete(f"declared text blob contains NUL: {path!r}")
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if scanner._looks_text_path(path):
            raise ScanIncomplete(f"declared text blob is not UTF-8: {path!r}") from exc
        return None


def _scan_entries(scanner, root: Path, entries) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    scanned_bytes = 0
    for entry in sorted(entries, key=lambda item: item.path):
        if entry.issue is not None or entry.oid is None:
            raise ScanIncomplete(entry.issue or f"Git entry has no blob: {entry.path!r}")
        data = scanner._read_blob(root, entry.oid)
        scanned_bytes += len(data)
        if scanned_bytes > scanner.MAX_TOTAL_BLOB_BYTES:
            raise ScanIncomplete("repository aggregate blob-byte limit was reached")
        text = _decode_blob(scanner, entry.path, data)
        if text is not None:
            findings.extend(scan_prose(text, source=entry.path))
        if len(findings) >= MAX_FINDINGS:
            break
    return tuple(findings[:MAX_FINDINGS])


def _scan_repository(*, index: bool, tree: str | None, paths: list[str]) -> tuple[Finding, ...]:
    scanner = _content_scanner()
    try:
        root = scanner._repository_root()
        entries = (
            scanner._index_entries(root, paths)
            if index
            else scanner._tree_entries(root, tree, paths)
        )
        if paths and not entries:
            raise ScanIncomplete("requested pathspecs matched no Git entries")
        return _scan_entries(scanner, root, entries)
    except scanner._GitError as exc:
        raise ScanIncomplete(str(exc)) from exc


def _scan_commits(revision: str) -> tuple[Finding, ...]:
    scanner = _content_scanner()
    try:
        root = scanner._repository_root()
        output = scanner._run_git(
            root, ["rev-list", f"--max-count={MAX_COMMITS + 1}", "--end-of-options", revision]
        )
        commits = output.decode("ascii").splitlines()
        if len(commits) > MAX_COMMITS:
            raise ScanIncomplete("commit range exceeds the count limit")
        findings: list[Finding] = []
        scanned_bytes = 0
        for commit in commits:
            if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit) is None:
                raise ScanIncomplete("Git returned a malformed commit identifier")
            oid, data = scanner._read_commit(root, commit)
            scanned_bytes += len(data)
            if scanned_bytes > scanner.MAX_TOTAL_BLOB_BYTES:
                raise ScanIncomplete("commit range exceeds the byte limit")
            findings.extend(scan_commit_object(data, source=f"<commit:{oid}>"))
            if len(findings) >= MAX_FINDINGS:
                break
        return tuple(findings[:MAX_FINDINGS])
    except (UnicodeDecodeError, scanner._GitError) as exc:
        raise ScanIncomplete(str(exc)) from exc


def _git_identity(variable: str) -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["git", "var", variable],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanIncomplete(f"cannot read {variable}") from exc
    if result.returncode != 0 or len(result.stdout) > 16 * 1024:
        raise ScanIncomplete(f"cannot read {variable}")
    try:
        value = result.stdout.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise ScanIncomplete(f"{variable} is not UTF-8") from exc
    return _parse_git_identity(value, label=variable)


def _bounded_file(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_STDIN_BYTES + 1)
    except OSError as exc:
        raise ScanIncomplete(f"cannot read {path}") from exc
    if len(data) > MAX_STDIN_BYTES:
        raise ScanIncomplete(f"{path} exceeds the input limit")
    return data


def _prose_bytes(
        data: bytes, *, source: str, markdown: bool | None = None) -> tuple[Finding, ...]:
    if b"\x00" in data:
        raise ScanIncomplete(f"{source} contains NUL")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanIncomplete(f"{source} is not valid UTF-8") from exc
    return scan_prose(text, source=source, markdown=markdown)


def _report(findings: tuple[Finding, ...]) -> int:
    for finding in findings:
        print(
            f"{finding.source}:{finding.line}: {finding.code}: {finding.detail}",
            file=sys.stderr,
        )
    if findings:
        print("Remove it. The attribution rule has no exceptions.", file=sys.stderr)
        return 1
    print("attribution: clean")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="scan exact artifacts for explicit AI credit")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--index", action="store_true")
    selector.add_argument("--tree", metavar="COMMIT")
    selector.add_argument("--commits", metavar="REVISION")
    selector.add_argument("--commit", metavar="COMMIT")
    selector.add_argument("--message-file", type=Path)
    selector.add_argument("--stdin", dest="stdin_name", metavar="NAME")
    parser.add_argument("--input-format", choices=("plain", "markdown"))
    parser.add_argument("paths", nargs="*")
    arguments = parser.parse_args(argv)
    try:
        if arguments.input_format is not None and arguments.stdin_name is None:
            raise ScanIncomplete("input format applies only to stdin")
        if arguments.index or arguments.tree is not None:
            findings = _scan_repository(
                index=arguments.index, tree=arguments.tree, paths=arguments.paths
            )
        elif arguments.commits is not None:
            if arguments.paths:
                raise ScanIncomplete("commit-range scanning takes no pathspecs")
            findings = _scan_commits(arguments.commits)
        elif arguments.commit is not None:
            if arguments.paths:
                raise ScanIncomplete("commit scanning takes no pathspecs")
            scanner = _content_scanner()
            root = scanner._repository_root()
            oid, data = scanner._read_commit(root, arguments.commit)
            findings = scan_commit_object(data, source=f"<commit:{oid}>")
        elif arguments.message_file is not None:
            if arguments.paths:
                raise ScanIncomplete("message scanning takes no pathspecs")
            findings = list(
                _prose_bytes(
                    _bounded_file(arguments.message_file), source=os.fspath(arguments.message_file)
                )
            )
            for variable in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
                name, email = _git_identity(variable)
                findings.extend(scan_identity(name, email, source=f"<{variable}>"))
            findings = tuple(findings[:MAX_FINDINGS])
        else:
            if not arguments.stdin_name or arguments.paths:
                raise ScanIncomplete("stdin scanning requires one non-empty label")
            data = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
            if len(data) > MAX_STDIN_BYTES:
                raise ScanIncomplete("stdin exceeds the input limit")
            findings = _prose_bytes(
                data,
                source=arguments.stdin_name,
                markdown=arguments.input_format == "markdown",
            )
    except (OSError, ScanIncomplete) as exc:
        print(f"attribution scan incomplete: {exc}", file=sys.stderr)
        return 2
    return _report(findings)


if __name__ == "__main__":
    raise SystemExit(main())
