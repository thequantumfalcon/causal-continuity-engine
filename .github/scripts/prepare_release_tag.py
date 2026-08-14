"""Fail-closed owner workflow for creating and optionally pushing a release tag."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REPOSITORY = "thequantumfalcon/causal-continuity-engine"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
SIGNATURE_MARKERS = (
    "-----BEGIN PGP SIGNATURE-----",
    "-----BEGIN SSH SIGNATURE-----",
)
GIT_OPERATION_TIMEOUT_SECONDS = 120


def _load_release_checker() -> ModuleType:
    path = ROOT / ".github" / "scripts" / "check_release_tag.py"
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_release_tag_checker", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release tag checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = _load_release_checker()


def _run_git(*args: str) -> str:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *args],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=GIT_OPERATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            f"git {' '.join(args)} timed out after "
            f"{GIT_OPERATION_TIMEOUT_SECONDS}s") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no detail"
        raise SystemExit(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def _git_status(*args: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", *args],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=GIT_OPERATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            f"git {' '.join(args)} timed out after "
            f"{GIT_OPERATION_TIMEOUT_SECONDS}s") from exc


def _canonical_origin(url: str) -> bool:
    base = f"github.com/{EXPECTED_REPOSITORY}"
    allowed = {
        f"https://{base}",
        f"https://{base}.git",
        f"git@{base.replace('/', ':', 1)}",
        f"git@{base.replace('/', ':', 1)}.git",
        f"ssh://git@{base}",
        f"ssh://git@{base}.git",
    }
    return url.rstrip("/") in allowed


def _require_clean_tree() -> None:
    dirty = _run_git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise SystemExit("release tagging requires a completely clean working tree")


def _require_origin_identity() -> None:
    fetch_url = _run_git("remote", "get-url", "origin")
    push_url = _run_git("remote", "get-url", "--push", "origin")
    if not _canonical_origin(fetch_url) or not _canonical_origin(push_url):
        raise SystemExit(
            f"origin fetch/push URLs must both name {EXPECTED_REPOSITORY}")


def _remote_main_sha() -> str:
    completed = _git_status(
        "ls-remote", "--exit-code", "--heads", "origin", "refs/heads/main")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "main was not returned"
        raise SystemExit(f"cannot resolve exact origin/main: {detail}")
    lines = [line for line in completed.stdout.splitlines() if line]
    if len(lines) != 1:
        raise SystemExit("origin returned an ambiguous main reference")
    sha, separator, ref = lines[0].partition("\t")
    if separator != "\t" or ref != "refs/heads/main" or not re.fullmatch(
            r"[0-9a-f]{40,64}", sha):
        raise SystemExit("origin returned malformed main reference metadata")
    return sha


def _require_current_origin_main() -> str:
    branch = _run_git("symbolic-ref", "--short", "HEAD")
    if branch != "main":
        raise SystemExit("release tagging requires the checked-out main branch")
    _run_git(
        "fetch", "--no-tags", "origin",
        "refs/heads/main:refs/remotes/origin/main",
    )
    head = _run_git("rev-parse", "HEAD")
    tracked = _run_git("rev-parse", "refs/remotes/origin/main")
    remote = _remote_main_sha()
    if head != tracked or head != remote:
        raise SystemExit(
            "HEAD must exactly equal the freshly fetched and remotely observed origin/main")
    return head


def _local_tag_exists(tag: str) -> bool:
    completed = _git_status(
        "show-ref", "--verify", "--quiet", f"refs/tags/{tag}")
    if completed.returncode not in (0, 1):
        raise SystemExit("cannot determine whether the local release tag exists")
    return completed.returncode == 0


def _require_remote_tag_absent(tag: str) -> None:
    completed = _git_status(
        "ls-remote", "--exit-code", "--tags", "origin", f"refs/tags/{tag}")
    if completed.returncode == 0:
        raise SystemExit(f"remote release tag {tag} already exists")
    if completed.returncode != 2:
        detail = completed.stderr.strip() or "unexpected git ls-remote status"
        raise SystemExit(f"cannot prove remote tag absence: {detail}")


def _verify_metadata(tag: str) -> str:
    metadata_version = CHECKER._verify_release_metadata(tag)
    package_version = CHECKER._release_version()
    if metadata_version != package_version:
        raise SystemExit(
            "package, CFF, changelog, and release version metadata disagree")
    return package_version


def _verify_commit_and_checks(head: str) -> None:
    CHECKER._verify_github_commit(head, EXPECTED_REPOSITORY)
    CHECKER._verify_required_checks(
        head,
        repository=EXPECTED_REPOSITORY,
        source_root=ROOT,
    )


def _validate_local_tag(tag: str, head: str) -> str:
    ref = f"refs/tags/{tag}"
    if _run_git("cat-file", "-t", ref) != "tag":
        raise SystemExit("created release ref is not an annotated tag object")
    tag_bytes = CHECKER._git_bytes("cat-file", "tag", ref)
    CHECKER._scan_tag_object(tag, tag_bytes)
    try:
        body = tag_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("created release tag object is not valid UTF-8") from exc
    headers = CHECKER._signed_tag_headers(body)
    if headers.get("type") != "commit":
        raise SystemExit("created tag does not directly name a commit")
    if headers.get("tag") != tag:
        raise SystemExit("created tag object records the wrong exact tag name")
    if headers.get("object") != head:
        raise SystemExit("created tag object records a commit other than exact HEAD")
    if not any(marker in body for marker in SIGNATURE_MARKERS):
        raise SystemExit("created annotated tag has no PGP or SSH signature")
    tag_object = _run_git("rev-parse", f"{ref}^{{tag}}")
    CHECKER._verify_git_object_id(tag_object, "tag", tag_bytes)
    if _run_git("rev-parse", ref) != tag_object:
        raise SystemExit("release ref does not exactly resolve to its tag object")
    if _run_git("rev-parse", f"{ref}^{{commit}}") != head:
        raise SystemExit("release tag does not peel to exact HEAD")
    _run_git("verify-tag", tag)
    return tag_object


def _cleanup_created_tag(tag: str) -> None:
    _run_git("tag", "--delete", tag)
    if _local_tag_exists(tag):
        raise SystemExit(f"failed to remove locally created tag {tag}")


def _preflight(tag: str) -> tuple[str, str]:
    if TAG_RE.fullmatch(tag) is None:
        raise SystemExit("release tags must use exact stable vX.Y.Z form")
    _require_clean_tree()
    _require_origin_identity()
    head = _require_current_origin_main()
    if _local_tag_exists(tag):
        raise SystemExit(f"local release tag {tag} already exists")
    _require_remote_tag_absent(tag)
    version = _verify_metadata(tag)
    _verify_commit_and_checks(head)
    if _remote_main_sha() != head:
        raise SystemExit("origin/main advanced during release preflight")
    return head, version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument(
        "--push",
        action="store_true",
        help="push the validated tag to origin; never implied",
    )
    args = parser.parse_args(argv)

    head, version = _preflight(args.tag)
    created = False
    try:
        _run_git(
            "tag", "--sign", "--annotate", args.tag,
            "--message", f"Release {args.tag}",
        )
        created = True
        tag_object = _validate_local_tag(args.tag, head)
        if args.push:
            if _remote_main_sha() != head:
                raise SystemExit("origin/main advanced before tag push")
            # Keep this the final remote observation before the push below.
            _require_remote_tag_absent(args.tag)
    # Once this process creates the ref, every validation failure under our
    # control must remove it. Limiting cleanup to SystemExit would strand a tag
    # on an unexpected decode, API, or programming exception and invite a later
    # manual push that bypasses the pre-push rechecks.
    except (Exception, SystemExit, KeyboardInterrupt) as exc:
        if created:
            try:
                _cleanup_created_tag(args.tag)
            except SystemExit as cleanup_exc:
                raise SystemExit(
                    f"{exc}; cleanup also failed: {cleanup_exc}") from cleanup_exc
        raise

    if args.push:
        try:
            _run_git(
                "push", "--porcelain", "origin",
                f"refs/tags/{args.tag}:refs/tags/{args.tag}",
            )
        except SystemExit as exc:
            raise SystemExit(
                f"{exc}; validated local tag {args.tag} was retained") from exc
        print(
            f"pushed signed annotated {args.tag} ({tag_object}) "
            f"for package {version} at {head}")
    else:
        print(
            f"created signed annotated {args.tag} ({tag_object}) "
            f"for package {version} at {head}; not pushed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
