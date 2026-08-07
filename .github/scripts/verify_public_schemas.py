"""Verify that immutable public schema URLs serve checked-out schema bytes."""

from __future__ import annotations

import argparse
import ast
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW_ORIGIN = (
    "https://raw.githubusercontent.com/"
    "thequantumfalcon/causal-continuity-engine"
)
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
SCHEMA_VERSION_RE = re.compile(r"cce\.[a-z][a-z0-9-]*\.v[1-9][0-9]*\Z")
MAX_SCHEMA_BYTES = 2 * 1024 * 1024


def _runtime_schema_versions(root: Path) -> dict[str, str]:
    """Read the public schema registry without importing project code."""
    contract = root / "causal_continuity_engine" / "__init__.py"
    try:
        tree = ast.parse(contract.read_text(encoding="utf-8"), filename=str(contract))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise SystemExit("cannot parse the runtime SCHEMA_VERSIONS contract") from exc
    assignments = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == "SCHEMA_VERSIONS"
               for target in targets):
            assignments.append(node.value)
    if len(assignments) != 1:
        raise SystemExit("runtime must define SCHEMA_VERSIONS exactly once")
    assignment = assignments[0]
    try:
        versions = ast.literal_eval(assignment)
    except (ValueError, TypeError) as exc:
        raise SystemExit("SCHEMA_VERSIONS must be one literal mapping") from exc
    if (
        not isinstance(versions, dict)
        or not versions
        or not isinstance(assignment, ast.Dict)
        or len(assignment.keys) != len(versions)
        or any(not isinstance(key, str) or not key for key in versions)
        or any(
            not isinstance(value, str) or SCHEMA_VERSION_RE.fullmatch(value) is None
            for value in versions.values())
        or len(versions) != len(set(versions.values()))
    ):
        raise SystemExit("SCHEMA_VERSIONS is empty, duplicated, or noncanonical")
    return versions


def _schema_public_urls(root: Path) -> dict[str, str]:
    names = sorted(
        f"{version}.json" for version in _runtime_schema_versions(root).values())
    return {
        name: f"{RAW_ORIGIN}/v0.1.0/schemas/{name}"
        for name in names
    }


SCHEMA_PUBLIC_URLS = _schema_public_urls(ROOT)
SCHEMA_NAMES = tuple(SCHEMA_PUBLIC_URLS)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _document(data: bytes, *, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return payload


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/schema+json, application/json",
            "User-Agent": "causal-continuity-engine-release-verifier",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                raise SystemExit(
                    f"public schema request did not resolve exactly to {url}")
            data = response.read(MAX_SCHEMA_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise SystemExit(f"cannot fetch public schema {url}: {exc}") from exc
    if len(data) > MAX_SCHEMA_BYTES:
        raise SystemExit(f"public schema exceeds {MAX_SCHEMA_BYTES} bytes: {url}")
    return data


def _schema_urls(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(_schema_urls(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_schema_urls(child))
    elif isinstance(value, str) and value.startswith(f"{RAW_ORIGIN}/"):
        found.add(value.split("#", 1)[0])
    return found


def verify(
    root: Path,
    tag: str,
    *,
    fetch: Callable[[str], bytes] = _fetch,
) -> None:
    if TAG_RE.fullmatch(tag) is None:
        raise SystemExit("schema publication verification requires an exact vX.Y.Z tag")
    schema_dir = root / "schemas"
    schema_public_urls = _schema_public_urls(root)
    schema_names = tuple(schema_public_urls)
    actual = sorted(path.name for path in schema_dir.glob("*.json") if path.is_file())
    if actual != list(schema_names):
        raise SystemExit(
            "public schema inventory differs from the reviewed runtime contract")

    # A schema TypeURI identifies that schema version, not the package release
    # currently carrying it. Later package tags must continue to verify the
    # immutable v0.1.0 URLs instead of silently repointing the v1 identities.
    expected_urls = set(schema_public_urls.values())
    observed_ids: set[str] = set()
    for name in schema_names:
        local_path = schema_dir / name
        try:
            local_bytes = local_path.read_bytes()
        except OSError as exc:
            raise SystemExit(f"cannot read checked-out schema {local_path}") from exc
        local = _document(local_bytes, label=str(local_path))
        expected_url = schema_public_urls[name]
        committed_url = local.get("$id")
        if committed_url != expected_url:
            raise SystemExit(
                f"{name} has $id {committed_url!r}, expected {expected_url!r}")
        observed_ids.add(expected_url)
        unexpected_urls = _schema_urls(local) - expected_urls
        if unexpected_urls:
            raise SystemExit(
                f"{name} contains unreviewed or version-mismatched TypeURI URL(s): "
                + ", ".join(sorted(unexpected_urls)))

        # Fetch the committed identity itself. The explicit map above freezes
        # today's v1 contract; this variable makes the deciding path follow the
        # schema's checked-in $id rather than the current package tag.
        remote_bytes = fetch(committed_url)
        if not isinstance(remote_bytes, bytes):
            raise SystemExit("public schema fetcher returned non-byte content")
        remote = _document(remote_bytes, label=expected_url)
        if remote.get("$id") != expected_url:
            raise SystemExit(f"served schema has the wrong $id: {expected_url}")
        if remote_bytes != local_bytes:
            raise SystemExit(f"served schema bytes differ from checked-out {name}")

    if observed_ids != expected_urls:
        raise SystemExit("public schema $id set is incomplete or ambiguous")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    verify(ROOT, args.tag)
    print(
        f"all {len(_schema_public_urls(ROOT))} public schemas exactly match tagged bytes "
        f"for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
