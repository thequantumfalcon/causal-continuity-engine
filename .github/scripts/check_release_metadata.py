"""Validate version/date metadata in normal or tag-ready release mode."""

from __future__ import annotations

import argparse
import ast
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
RELEASE_HEADING_RE = re.compile(
    r"^## (?P<version>[0-9]+\.[0-9]+\.[0-9]+) — "
    r"(?P<state>not yet released|[0-9]{4}-[0-9]{2}-[0-9]{2})$",
    re.MULTILINE,
)
PRE_RELEASE_MARKERS = (
    "not yet released",
    "no release has been tagged",
    "repository carries no tags",
    "no tags at all",
    "because nothing has",
)
RESET_UNRELEASED_TEXT = "No unreleased changes."


def _runtime_version(root: Path) -> str:
    source = root / "causal_continuity_engine" / "__init__.py"
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise SystemExit("cannot parse the runtime version source") from exc
    versions = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__version__"
                    for target in node.targets)
        ):
            try:
                versions.append(ast.literal_eval(node.value))
            except (ValueError, TypeError) as exc:
                raise SystemExit("runtime __version__ must be a string literal") from exc
    if len(versions) != 1 or not isinstance(versions[0], str):
        raise SystemExit("runtime must define exactly one literal __version__")
    version = versions[0]
    if VERSION_RE.fullmatch(version) is None:
        raise SystemExit("release version must be stable X.Y.Z with no pre-release marker")
    return version


def _cff_fields(root: Path) -> dict[str, str]:
    try:
        text = (root / "CITATION.cff").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SystemExit("cannot read CITATION.cff") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(version|date-released):[ \t]*(.*)", line)
        if match is None:
            continue
        name, value = match.groups()
        if name in fields or not value or value != value.strip():
            raise SystemExit(f"CITATION.cff has malformed or duplicate {name}")
        fields[name] = value
    if "version" not in fields:
        raise SystemExit("CITATION.cff is missing its top-level version")
    return fields


def _iso_date(value: str, *, label: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise SystemExit(f"{label} must be a real ISO YYYY-MM-DD date") from exc
    if parsed.isoformat() != value:
        raise SystemExit(f"{label} must use canonical ISO YYYY-MM-DD form")
    return value


def _changelog_state(root: Path, version: str) -> tuple[str, str, str]:
    try:
        text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SystemExit("cannot read CHANGELOG.md") from exc
    headings = [
        match for match in RELEASE_HEADING_RE.finditer(text)
        if match.group("version") == version
    ]
    if len(headings) != 1:
        raise SystemExit(
            f"CHANGELOG.md must contain exactly one release heading for {version}")
    unreleased = re.search(
        r"^## Unreleased[ \t]*\n(?P<body>.*?)(?=^## )", text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if unreleased is None:
        raise SystemExit("CHANGELOG.md must contain an Unreleased section")
    return headings[0].group("state"), unreleased.group("body").strip(), text


def check(root: Path = ROOT, *, release_tag: str | None = None) -> tuple[str, str | None]:
    version = _runtime_version(root)
    cff = _cff_fields(root)
    if cff["version"] != version:
        raise SystemExit(
            f"CITATION.cff version {cff['version']!r} differs from runtime {version!r}")
    state, unreleased, changelog = _changelog_state(root, version)
    cff_date = cff.get("date-released")

    if state == "not yet released":
        if cff_date is not None:
            raise SystemExit(
                "unreleased metadata must not declare CITATION.cff date-released")
    else:
        release_date = _iso_date(state, label="CHANGELOG.md release date")
        if cff_date is None:
            raise SystemExit("released metadata requires CITATION.cff date-released")
        if _iso_date(cff_date, label="CITATION.cff date-released") != release_date:
            raise SystemExit("CHANGELOG.md and CITATION.cff release dates differ")

    if release_tag is not None:
        expected_tag = f"v{version}"
        if release_tag != expected_tag:
            raise SystemExit(
                f"release tag {release_tag!r} does not match package version "
                f"{expected_tag!r}")
        if state == "not yet released":
            raise SystemExit("release mode rejects a not yet released changelog heading")
        if unreleased != RESET_UNRELEASED_TEXT:
            raise SystemExit(
                "release mode requires the Unreleased section to be reset exactly to "
                f"{RESET_UNRELEASED_TEXT!r}")
        lowered = changelog.casefold()
        stale = [marker for marker in PRE_RELEASE_MARKERS if marker in lowered]
        if stale:
            raise SystemExit(
                "release mode found stale pre-release marker(s): " + ", ".join(stale))
    return version, None if state == "not yet released" else state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release", metavar="TAG",
        help="require tag-ready released metadata for exactly TAG",
    )
    args = parser.parse_args(argv)
    version, release_date = check(ROOT, release_tag=args.release)
    if args.release is None:
        state = "unreleased" if release_date is None else f"released {release_date}"
        print(f"release metadata is internally consistent for {version} ({state})")
    else:
        print(f"release metadata is tag-ready for {args.release} on {release_date}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
