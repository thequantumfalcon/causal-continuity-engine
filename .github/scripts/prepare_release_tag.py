"""Fail-closed owner workflow for creating and optionally pushing a release tag."""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REPOSITORY = "thequantumfalcon/causal-continuity-engine"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")


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
RELEASE_SSH_ORIGIN = CHECKER.RELEASE_SSH_ORIGIN
_RELEASE_GIT = None


def _set_release_git(release_git):
    global _RELEASE_GIT
    previous = _RELEASE_GIT
    _RELEASE_GIT = release_git
    checker_previous = CHECKER._set_release_git(release_git)
    return previous, checker_previous


def _restore_release_git(previous) -> None:
    global _RELEASE_GIT
    _RELEASE_GIT, checker_previous = previous
    CHECKER._set_release_git(checker_previous)


def _release_git():
    if _RELEASE_GIT is None:
        raise SystemExit("release Git profile is not configured")
    return _RELEASE_GIT


def _run_git(*args: str) -> str:
    return _release_git().output(*args)


def _git_status(*args: str) -> subprocess.CompletedProcess[str]:
    return _release_git().run(*args)


def _canonical_origin(url: str) -> bool:
    return url == RELEASE_SSH_ORIGIN


def _require_clean_tree() -> None:
    dirty = _run_git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise SystemExit("release tagging requires a completely clean working tree")


def _require_origin_identity() -> None:
    if not _canonical_origin(_release_git().origin_url):
        raise SystemExit(
            f"origin fetch/push URLs must both name {EXPECTED_REPOSITORY} over SSH")


def _remote_main_sha() -> str:
    completed = _git_status(
        "ls-remote", "--exit-code", "--heads", RELEASE_SSH_ORIGIN,
        "refs/heads/main")
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
        "fetch", "--no-tags", RELEASE_SSH_ORIGIN,
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
        "ls-remote", "--exit-code", "--tags", RELEASE_SSH_ORIGIN,
        f"refs/tags/{tag}")
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
    if "-----BEGIN SSH SIGNATURE-----" not in body:
        raise SystemExit("created annotated tag has no SSH signature")
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


def _build_release_git(args: argparse.Namespace):
    required = {
        "--git-executable": args.git_executable,
        "--tagger-name": args.tagger_name,
        "--tagger-email": args.tagger_email,
        "--signing-key": args.signing_key,
        "--ssh-keygen-executable": args.ssh_keygen_executable,
        "--allowed-signers-file": args.allowed_signers_file,
        "--ssh-executable": args.ssh_executable,
        "--known-hosts-file": args.known_hosts_file,
        "--transport-key": args.transport_key,
        "--ssh-auth-sock": args.ssh_auth_sock,
    }
    missing = [option for option, value in required.items() if value is None]
    if missing:
        raise SystemExit(
            "explicit SSH release profile requires: " + ", ".join(missing))
    return CHECKER.ReleaseGit.owner_profile(
        root=ROOT,
        git_executable=args.git_executable,
        tagger_name=args.tagger_name,
        tagger_email=args.tagger_email,
        signing_key=args.signing_key,
        ssh_keygen_executable=args.ssh_keygen_executable,
        allowed_signers_file=args.allowed_signers_file,
        ssh_executable=args.ssh_executable,
        known_hosts_file=args.known_hosts_file,
        transport_key=args.transport_key,
        ssh_auth_sock=args.ssh_auth_sock,
    )


def main(
    argv: list[str] | None = None,
    *,
    release_git=None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--git-executable")
    parser.add_argument("--tagger-name")
    parser.add_argument("--tagger-email")
    parser.add_argument("--signing-key")
    parser.add_argument("--ssh-keygen-executable")
    parser.add_argument("--allowed-signers-file")
    parser.add_argument("--ssh-executable")
    parser.add_argument("--known-hosts-file")
    parser.add_argument("--transport-key")
    parser.add_argument("--ssh-auth-sock")
    parser.add_argument(
        "--push",
        action="store_true",
        help="push the validated tag to origin; never implied",
    )
    args = parser.parse_args(argv)
    owned = release_git is None
    if release_git is None:
        release_git = _build_release_git(args)
    previous = _set_release_git(release_git)
    try:
        head, version = _preflight(args.tag)
        created = False
        creation_attempted = False
        try:
            creation_attempted = True
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
        # Once this process attempts to create the previously absent ref, every
        # failure must inspect and remove it if it exists. A signal or lost child
        # response can follow the ref update even when Git never returns success.
        except (Exception, SystemExit, KeyboardInterrupt) as exc:
            if creation_attempted and not created:
                try:
                    created = _local_tag_exists(args.tag)
                except (Exception, SystemExit, KeyboardInterrupt) as inspect_exc:
                    raise SystemExit(
                        f"{exc}; the local tag may exist and could not be inspected: "
                        f"{inspect_exc}") from inspect_exc
            if created:
                try:
                    _cleanup_created_tag(args.tag)
                except (Exception, SystemExit, KeyboardInterrupt) as cleanup_exc:
                    raise SystemExit(
                        f"{exc}; local tag cleanup failed and the local tag may remain: "
                        f"{cleanup_exc}") from cleanup_exc
            raise

        if args.push:
            try:
                _run_git(
                    "push", "--porcelain", "--no-verify", RELEASE_SSH_ORIGIN,
                    f"refs/tags/{args.tag}:refs/tags/{args.tag}",
                )
            except (Exception, SystemExit, KeyboardInterrupt) as exc:
                raise SystemExit(
                    f"{exc}; the remote tag may already exist and validated local tag "
                    f"{args.tag} was retained") from exc
            print(
                f"pushed signed annotated {args.tag} ({tag_object}) "
                f"for package {version} at {head}")
        else:
            print(
                f"created signed annotated {args.tag} ({tag_object}) "
                f"for package {version} at {head}; not pushed")
        return 0
    finally:
        _restore_release_git(previous)
        if owned:
            release_git.close()


if __name__ == "__main__":
    raise SystemExit(main())
