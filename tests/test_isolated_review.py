"""Adversarial coverage for the one-way external-review boundary."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent

# The reviewed boundary is a POSIX mechanism: it needs grp, pwd, resource and
# Seatbelt confinement, none of which exist on Windows. Importing the launcher
# there raises ModuleNotFoundError, so skip the module rather than assert a
# portability this control neither has nor claims. docs/CONTENT-INGRESS-
# FIREWALL.md documents it as macOS-only.
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="isolated review is POSIX-only (grp, pwd, resource, Seatbelt)",
)


def _load_boundary():
    path = ROOT / ".github" / "scripts" / "run_isolated_review.py"
    spec = importlib.util.spec_from_file_location("cce_isolated_review_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _repository(tmp_path: Path) -> Path:
    repo = tmp_path / "repository"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "tracked.txt").write_bytes(b"tracked\n")
    _git(repo, "add", "tracked.txt")
    return repo


def _identity(boundary, home: Path, *, uid: int | None = None):
    # Never create a directory outside the test's own tmp_path. /var/empty
    # already exists on macOS, so mkdir was a silent no-op there, but on Linux
    # it attempts to create it under /var and is denied.
    home.mkdir(parents=True, exist_ok=True)
    return boundary.ReviewerIdentity(
        "reviewer",
        os.getuid() if uid is None else uid,
        os.getgid(),
        home,
        (os.getgid(),),
    )


def test_snapshot_is_git_free_and_copies_current_bytes_to_new_plain_inodes(tmp_path):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    (repo / "tracked.txt").write_bytes(b"working tree\n")
    (repo / "untracked.txt").write_bytes(b"untracked\n")
    (repo / "ignored.txt").write_bytes(b"ignored\n")
    (repo / ".gitignore").write_bytes(b"ignored.txt\n")
    _git(repo, "add", ".gitignore")
    source_xattr = b"user.org.cce.source-only"
    if hasattr(os, "setxattr"):
        os.setxattr(repo / "tracked.txt", source_xattr, b"source-only")
    else:
        subprocess.run(
            [
                "/usr/bin/xattr",
                "-w",
                os.fsdecode(source_xattr),
                "source-only",
                repo / "tracked.txt",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    snapshot = tmp_path / "quarantine" / "snapshot"
    snapshot.parent.mkdir()
    entries = boundary.export_snapshot(repo, snapshot)

    assert (snapshot / "tracked.txt").read_bytes() == b"working tree\n"
    assert (snapshot / "untracked.txt").read_bytes() == b"untracked\n"
    assert not (snapshot / "ignored.txt").exists()
    assert not (snapshot / ".git").exists()
    assert os.stat(snapshot / "tracked.txt").st_ino != os.stat(repo / "tracked.txt").st_ino
    assert os.stat(snapshot / "tracked.txt").st_nlink == 1
    destination_xattrs = boundary._xattr_names(os.fsencode(snapshot / "tracked.txt"))
    assert source_xattr not in destination_xattrs
    assert set(destination_xattrs) <= {b"com.apple.provenance"}
    assert [entry.file_id for entry in entries] == list(range(1, len(entries) + 1))
    assert {entry.relative_path for entry in entries} == {
        b".gitignore",
        b"tracked.txt",
        b"untracked.txt",
    }


@pytest.mark.parametrize("source_kind", ["symlink", "fifo", "gitlink"])
def test_snapshot_rejects_non_plain_source_entries(tmp_path, source_kind):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    if source_kind == "symlink":
        (repo / "link").symlink_to("tracked.txt")
        _git(repo, "add", "link")
    elif source_kind == "fifo":
        os.mkfifo(repo / "pipe")
    else:
        empty_tree = subprocess.check_output(
            ["git", "-C", os.fspath(repo), "mktree"], input=b""
        ).decode("ascii").strip()
        commit = subprocess.check_output(
            ["git", "-C", os.fspath(repo), "commit-tree", empty_tree],
            input=b"gitlink fixture\n",
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            },
        ).decode("ascii").strip()
        _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{commit},dependency")

    with pytest.raises(boundary.BoundaryError, match="symlink|unsupported|gitlink"):
        boundary.export_snapshot(repo, tmp_path / "snapshot")


def test_snapshot_detects_source_metadata_race_after_initial_digest(tmp_path, monkeypatch):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    original = boundary._stable_file_digest
    changed = False

    def race(path, expected):
        nonlocal changed
        digest = original(path, expected)
        if not changed and os.fsdecode(path).endswith("tracked.txt"):
            changed = True
            os.utime(path, ns=(expected.st_atime_ns, expected.st_mtime_ns + 1))
        return digest

    monkeypatch.setattr(boundary, "_stable_file_digest", race)
    with pytest.raises(boundary.BoundaryError, match="changed"):
        boundary.export_snapshot(repo, tmp_path / "snapshot")


def test_snapshot_rejects_source_hardlink(tmp_path):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    os.link(repo / "tracked.txt", tmp_path / "external-alias")

    with pytest.raises(boundary.BoundaryError, match="hardlink"):
        boundary.export_snapshot(repo, tmp_path / "snapshot")


def test_protected_manifest_records_hardlink_and_metadata_changes(tmp_path):
    boundary = _load_boundary()
    protected = tmp_path / "protected"
    protected.mkdir()
    original = protected / "state"
    original.write_bytes(b"state\n")
    alias = protected / "alias"
    os.link(original, alias)

    before = boundary.protected_manifest((protected,))
    alias.unlink()
    after = boundary.protected_manifest((protected,))

    assert boundary._changed_entries(before, after)


def test_rejected_in_repo_quarantine_is_not_created(tmp_path):
    boundary = _load_boundary()
    protected = tmp_path / "protected"
    protected.mkdir()
    rejected = protected / "must-not-exist"

    with pytest.raises(boundary.BoundaryError, match="overlaps"):
        boundary._quarantine_path(os.fspath(rejected), (protected,))

    assert not rejected.exists()


def test_reviewer_identity_must_be_non_root_non_owner_and_unable_to_write(tmp_path, monkeypatch):
    boundary = _load_boundary()
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "state").write_bytes(b"state\n")
    owner = os.stat(protected).st_uid

    monkeypatch.setattr(boundary.os, "geteuid", lambda: owner)
    with pytest.raises(boundary.BoundaryError, match="supervisor must run as root"):
        boundary.require_supervisor_and_reviewer("reviewer", (protected,))

    home = tmp_path / "reviewer-home"
    home.mkdir()
    account = SimpleNamespace(
        pw_name="reviewer",
        pw_uid=owner,
        pw_gid=999,
        pw_dir=os.fspath(home),
        pw_shell="/usr/bin/false",
    )
    monkeypatch.setattr(boundary.os, "geteuid", lambda: 0)
    monkeypatch.setattr(boundary.pwd, "getpwnam", lambda name: account)
    monkeypatch.setattr(boundary.os, "getgrouplist", lambda name, gid: [gid])
    monkeypatch.setattr(boundary.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="reviewers"))
    with pytest.raises(boundary.BoundaryError, match="different accounts"):
        boundary.require_supervisor_and_reviewer("reviewer", (protected,))

    account.pw_uid = owner + 1
    monkeypatch.setattr(boundary, "_reviewer_has_sudo_privilege", lambda identity: False)
    monkeypatch.setattr(boundary, "_uid_processes", lambda uid: ())
    monkeypatch.setattr(
        boundary,
        "_reviewer_cannot_write_protected",
        lambda identity, roots: (_ for _ in ()).throw(boundary.BoundaryError("writable")),
    )
    with pytest.raises(boundary.BoundaryError, match="writable"):
        boundary.require_supervisor_and_reviewer("reviewer", (protected,))


def test_seatbelt_profile_is_default_write_deny_with_narrow_quarantine(tmp_path):
    boundary = _load_boundary()
    protected = (tmp_path / "repository", tmp_path / "linked-worktree")
    for path in protected:
        path.mkdir()
    quarantine = tmp_path / "quarantine"
    snapshot = quarantine / "snapshot"
    identity = _identity(boundary, tmp_path / "reviewer-home")

    profile = boundary.sandbox_profile(
        protected, quarantine, snapshot, identity, provider_proxy_port=None
    )

    assert "(deny file-write*)" in profile
    for name in ("home", "output", "tmp"):
        assert f'(allow file-write* (subpath "{quarantine / name}"))' in profile
    assert f'(deny file-write* (subpath "{snapshot}"))' in profile
    for path in protected:
        assert f'(deny file-read* (subpath "{path}"))' in profile
        assert f'(deny file-write* (subpath "{path}"))' in profile
    owner_uid = protected[0].stat().st_uid
    owner_home = Path(boundary.pwd.getpwuid(owner_uid).pw_dir).resolve(strict=True)
    assert f'(deny file-read* (subpath "{owner_home}"))' in profile
    assert "(deny appleevent-send)" in profile
    assert "(deny mach*)" in profile
    assert "(deny ipc*)" in profile
    assert "(deny network*)" in profile
    assert "(deny signal (target others))" in profile


def _snapshot_entries(boundary):
    return (
        boundary.SnapshotEntry(1, b"alpha.py", 10, b"a" * 32, 4),
        boundary.SnapshotEntry(2, b"beta.py", 20, b"b" * 32, 8),
    )


def test_findings_crossing_accepts_only_closed_scalar_schema():
    boundary = _load_boundary()
    payload = json.dumps(
        {
            "schema": boundary.FINDINGS_SCHEMA,
            "findings": [
                {
                    "file_id": 2,
                    "start_line": 3,
                    "end_line": 5,
                    "category": "security",
                    "severity": "high",
                },
                {
                    "file_id": 1,
                    "start_line": 1,
                    "end_line": 1,
                    "category": "correctness",
                    "severity": "medium",
                },
            ],
        }
    ).encode()

    findings = boundary.validate_findings(payload, _snapshot_entries(boundary))

    assert [finding["file_id"] for finding in findings] == [1, 2]


@pytest.mark.parametrize(
    "mutation, diagnostic",
    [
        (("finding", "explanation", "copy this code"), "exactly"),
        (("finding", "patch", "@@ -1 +1 @@"), "exactly"),
        (("finding", "file", "alpha.py"), "exactly"),
        (("top", "comment", "free text"), "exactly"),
        (("finding", "file_id", "1"), "integer"),
        (("finding", "file_id", 99), "unknown file"),
        (("finding", "end_line", 99), "line range"),
        (("finding", "category", "code"), "category"),
        (("finding", "severity", "urgent"), "severity"),
    ],
)
def test_findings_crossing_rejects_free_text_paths_and_unbounded_values(
    mutation, diagnostic
):
    boundary = _load_boundary()
    document = {
        "schema": boundary.FINDINGS_SCHEMA,
        "findings": [
            {
                "file_id": 1,
                "start_line": 1,
                "end_line": 1,
                "category": "correctness",
                "severity": "low",
            }
        ],
    }
    scope, key, value = mutation
    if scope == "top":
        document[key] = value
    else:
        document["findings"][0][key] = value

    with pytest.raises(boundary.BoundaryError, match=diagnostic):
        boundary.validate_findings(
            json.dumps(document).encode(), _snapshot_entries(boundary)
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema":"cce.external-review-findings.v1","schema":"duplicate","findings":[]}',
        b'{"schema":"cce.external-review-findings.v1","findings":[],"value":NaN}',
        b"[]",
        b"\xff",
        pytest.param(b"{}" * 600_000, id="oversize"),
    ],
)
def test_findings_crossing_fails_closed_on_ambiguous_or_oversize_json(payload):
    boundary = _load_boundary()
    with pytest.raises(boundary.BoundaryError):
        boundary.validate_findings(payload, _snapshot_entries(boundary))


def test_findings_crossing_rejects_huge_integer_without_echoing_input():
    boundary = _load_boundary()
    huge = "9" * 100_000
    payload = (
        '{"schema":"cce.external-review-findings.v1","findings":['
        '{"file_id":' + huge + ',"start_line":1,"end_line":1,'
        '"category":"correctness","severity":"low"}]}'
    ).encode()

    with pytest.raises(boundary.BoundaryError) as captured:
        boundary.validate_findings(payload, _snapshot_entries(boundary))

    assert huge[:100] not in str(captured.value)


def test_review_command_requires_absolute_digest_bound_root_controlled_file(tmp_path, monkeypatch):
    boundary = _load_boundary()
    with pytest.raises(boundary.BoundaryError, match="absolute"):
        boundary._verify_review_command(["reviewer"], "0" * 64, ())

    command = tmp_path / "reviewer"
    command.write_bytes(b"trusted fixture")
    monkeypatch.setattr(boundary, "_trusted_file_digest", lambda path: b"a" * 32)
    with pytest.raises(boundary.BoundaryError, match="does not match"):
        boundary._verify_review_command([os.fspath(command)], "b" * 64, ())


@pytest.mark.parametrize("privileged_bit", [stat.S_ISUID, stat.S_ISGID])
def test_trusted_executable_rejects_privileged_mode_bits(monkeypatch, privileged_bit):
    boundary = _load_boundary()
    directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    executable = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o755 | privileged_bit,
        st_uid=0,
    )

    def lstat(path):
        return executable if Path(path) == Path("/trusted/reviewer") else directory

    monkeypatch.setattr(boundary.os, "lstat", lstat)
    with pytest.raises(boundary.BoundaryError, match="privileged mode bit"):
        boundary._trusted_file_digest(Path("/trusted/reviewer"))


def test_quarantine_parent_requires_root_owner_or_root_sticky(monkeypatch):
    boundary = _load_boundary()

    def info(uid, mode):
        return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)

    monkeypatch.setattr(boundary.os, "lstat", lambda path: info(501, 0o755))
    with pytest.raises(boundary.BoundaryError, match="root-controlled"):
        boundary._safe_quarantine_parent(Path("/parent"))
    monkeypatch.setattr(boundary.os, "lstat", lambda path: info(0, 0o777))
    with pytest.raises(boundary.BoundaryError, match="replaceable"):
        boundary._safe_quarantine_parent(Path("/parent"))
    monkeypatch.setattr(
        boundary.os, "lstat", lambda path: info(0, stat.S_ISVTX | 0o777)
    )
    boundary._safe_quarantine_parent(Path("/private/tmp"))


def test_provider_proxy_must_use_a_privileged_port(tmp_path, monkeypatch):
    boundary = _load_boundary()
    monkeypatch.setattr(boundary.sys, "platform", "darwin")
    monkeypatch.setattr(boundary, "_verify_trusted_runtime", lambda: None)
    with pytest.raises(boundary.BoundaryError, match="proxy port"):
        boundary.run_isolated_review(
            tmp_path,
            ["/reviewer"],
            reviewer_user="reviewer",
            command_sha256="0" * 64,
            provider_proxy_port=65_535,
        )


def test_trusted_runtime_path_rejects_writable_ancestor(monkeypatch):
    boundary = _load_boundary()
    trusted = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    untrusted = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=501)

    def lstat(path):
        return untrusted if Path(path) == Path("/unsafe") else trusted

    monkeypatch.setattr(boundary.os, "lstat", lstat)
    with pytest.raises(boundary.BoundaryError, match="root-controlled"):
        boundary._verify_trusted_directory(Path("/unsafe/root-owned-leaf"))


def test_quarantine_usage_is_bounded(tmp_path, monkeypatch):
    boundary = _load_boundary()
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    (quarantine / "output").write_bytes(b"x" * 16)
    monkeypatch.setattr(boundary, "MAX_QUARANTINE_BYTES", 8)

    with pytest.raises(boundary.BoundaryError, match="byte limit"):
        boundary._quarantine_usage(quarantine)


def test_clean_child_environment_does_not_inherit_parent_credentials(tmp_path):
    boundary = _load_boundary()
    snapshot = tmp_path / "quarantine" / "snapshot"
    quarantine = snapshot.parent
    identity = _identity(boundary, tmp_path / "reviewer-home")
    environment = boundary.clean_child_environment(
        snapshot,
        quarantine,
        identity=identity,
        provider_proxy_port=None,
    )

    assert environment["CCE_REVIEW_SNAPSHOT"] == os.fspath(snapshot)
    assert environment["CCE_REVIEW_QUARANTINE"] == os.fspath(quarantine)
    assert environment["PATH"] != "/attacker/path"
    assert "GH_TOKEN" not in environment
    assert "REVIEW_API_TOKEN" not in environment
    assert "GIT_DIR" not in environment


def test_review_refuses_preexisting_external_alias_to_protected_git_file_before_launch(
    tmp_path, monkeypatch
):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    os.link(repo / ".git" / "config", tmp_path / "external-alias")
    quarantine = tmp_path / "quarantine"
    reviewer_launched = False

    monkeypatch.setattr(boundary.sys, "platform", "darwin")
    identity = _identity(boundary, tmp_path / "reviewer-home")
    monkeypatch.setattr(boundary, "_verify_trusted_runtime", lambda: None)
    monkeypatch.setattr(
        boundary,
        "require_supervisor_and_reviewer",
        lambda user, roots: identity,
    )
    monkeypatch.setattr(boundary, "_safe_quarantine_parent", lambda parent: None)
    monkeypatch.setattr(boundary, "_verify_review_command", lambda *args: None)
    monkeypatch.setattr(boundary, "_run_seatbelt_negative_control", lambda *args: None)
    monkeypatch.setattr(boundary, "_require_no_reviewer_processes", lambda identity: None)
    monkeypatch.setattr(boundary, "_quarantine_usage", lambda path: (1, 0))
    monkeypatch.setattr(boundary, "_sandbox_executable", lambda: Path("/sandbox"))

    def reviewer(*args, **kwargs):
        nonlocal reviewer_launched
        reviewer_launched = True
        raise AssertionError("reviewer launched")

    monkeypatch.setattr(boundary, "_run_command", reviewer)

    with pytest.raises(boundary.BoundaryError, match="exactly one link"):
        boundary.run_isolated_review(
            repo,
            ["/reviewer"],
            reviewer_user="reviewer",
            command_sha256="0" * 64,
            quarantine_dir=os.fspath(quarantine),
        )

    assert not reviewer_launched


def test_review_rechecks_protected_link_count_after_export(tmp_path, monkeypatch):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    quarantine = tmp_path / "quarantine"
    negative_control_launched = False
    reviewer_launched = False

    monkeypatch.setattr(boundary.sys, "platform", "darwin")
    identity = _identity(boundary, tmp_path / "reviewer-home")
    monkeypatch.setattr(boundary, "_verify_trusted_runtime", lambda: None)
    monkeypatch.setattr(
        boundary,
        "require_supervisor_and_reviewer",
        lambda user, roots: identity,
    )
    monkeypatch.setattr(boundary, "_safe_quarantine_parent", lambda parent: None)
    monkeypatch.setattr(boundary, "_verify_review_command", lambda *args: None)
    monkeypatch.setattr(boundary, "_require_no_reviewer_processes", lambda identity: None)
    monkeypatch.setattr(boundary, "_quarantine_usage", lambda path: (1, 0))
    monkeypatch.setattr(boundary, "_sandbox_executable", lambda: Path("/sandbox"))
    real_export = boundary.export_snapshot

    def export_then_alias(root, snapshot):
        entries = real_export(root, snapshot)
        os.link(repo / ".git" / "config", tmp_path / "external-alias")
        return entries

    def negative_control(*args, **kwargs):
        nonlocal negative_control_launched
        negative_control_launched = True
        raise AssertionError("negative control launched")

    def reviewer(*args, **kwargs):
        nonlocal reviewer_launched
        reviewer_launched = True
        raise AssertionError("reviewer launched")

    monkeypatch.setattr(boundary, "export_snapshot", export_then_alias)
    monkeypatch.setattr(boundary, "_run_seatbelt_negative_control", negative_control)
    monkeypatch.setattr(boundary, "_run_command", reviewer)

    with pytest.raises(boundary.BoundaryError, match="exactly one link"):
        boundary.run_isolated_review(
            repo,
            ["/reviewer"],
            reviewer_user="reviewer",
            command_sha256="0" * 64,
            quarantine_dir=os.fspath(quarantine),
        )

    assert not negative_control_launched
    assert not reviewer_launched


def test_postflight_runs_even_when_review_command_fails(tmp_path, monkeypatch):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    quarantine = tmp_path / "quarantine"
    calls = []

    monkeypatch.setattr(boundary.sys, "platform", "darwin")
    identity = _identity(boundary, tmp_path / "reviewer-home")
    monkeypatch.setattr(boundary, "_verify_trusted_runtime", lambda: None)
    monkeypatch.setattr(
        boundary,
        "require_supervisor_and_reviewer",
        lambda user, roots: identity,
    )
    monkeypatch.setattr(boundary, "_safe_quarantine_parent", lambda parent: None)
    monkeypatch.setattr(boundary, "_verify_review_command", lambda *args: None)
    monkeypatch.setattr(boundary, "_run_seatbelt_negative_control", lambda *args: None)
    monkeypatch.setattr(boundary, "_require_no_reviewer_processes", lambda identity: None)
    monkeypatch.setattr(boundary, "_quarantine_usage", lambda path: (1, 0))
    monkeypatch.setattr(boundary, "_sandbox_executable", lambda: Path("/sandbox"))
    real_manifest = boundary.protected_manifest

    def manifest(roots):
        calls.append("manifest")
        return real_manifest(roots)

    class Result:
        returncode = 7
        stdout = b"not accepted on a failed command"

    monkeypatch.setattr(boundary, "protected_manifest", manifest)
    monkeypatch.setattr(boundary, "_run_command", lambda *args, **kwargs: Result())

    status = boundary.run_isolated_review(
        repo,
        ["/reviewer"],
        reviewer_user="reviewer",
        command_sha256="0" * 64,
        quarantine_dir=os.fspath(quarantine),
    )

    assert status == boundary.REVIEW_COMMAND_FAILURE
    assert len(calls) == 5


def test_missing_start_marker_is_a_boundary_failure(tmp_path, monkeypatch):
    boundary = _load_boundary()
    quarantine = tmp_path / "quarantine"
    output = quarantine / "output"
    output.mkdir(parents=True)
    snapshot = quarantine / "snapshot"
    snapshot.mkdir()
    identity = _identity(boundary, tmp_path / "reviewer-home")

    class Process:
        pid = 999_999

        def wait(self, timeout=None):
            return 7

        def poll(self):
            return 7

    monkeypatch.setattr(boundary, "_require_no_reviewer_processes", lambda identity: None)
    monkeypatch.setattr(boundary, "_kill_reviewer_processes", lambda identity: None)
    monkeypatch.setattr(boundary.subprocess, "Popen", lambda *args, **kwargs: Process())

    def missing_group(pid, signal_number):
        raise ProcessLookupError

    monkeypatch.setattr(boundary.os, "killpg", missing_group)
    with pytest.raises(boundary.BoundaryError, match="did not cross"):
        boundary._run_command(
            Path("/sandbox"),
            "(version 1)(allow default)",
            ["/reviewer"],
            identity=identity,
            cwd=snapshot,
            environment={},
            quarantine=quarantine,
            timeout_seconds=1,
            output_stem="review",
            command_status=True,
        )


def test_start_marker_accepts_only_exact_reviewer_owned_plain_file(tmp_path):
    boundary = _load_boundary()
    identity = _identity(boundary, tmp_path / "reviewer-home")
    token = "a" * 64
    marker = tmp_path / "marker"
    marker.write_text(token, encoding="ascii")

    boundary._read_start_marker(marker, token, identity)


def test_start_marker_rejects_symlink_without_following_it(tmp_path):
    boundary = _load_boundary()
    identity = _identity(boundary, tmp_path / "reviewer-home")
    target = tmp_path / "target"
    target.write_text("a" * 64, encoding="ascii")
    marker = tmp_path / "marker"
    marker.symlink_to(target)

    with pytest.raises(boundary.BoundaryError, match="did not cross"):
        boundary._read_start_marker(marker, "a" * 64, identity)


def test_start_marker_rejects_device():
    boundary = _load_boundary()
    device = Path("/dev/null")
    info = os.stat(device)
    identity = boundary.ReviewerIdentity(
        "reviewer", info.st_uid, info.st_gid, Path("/nonexistent-review-home"),
        (info.st_gid,)
    )

    with pytest.raises(boundary.BoundaryError, match="marker is invalid"):
        boundary._read_start_marker(device, "a" * 64, identity)


def test_start_marker_rejects_oversize_plain_file(tmp_path):
    boundary = _load_boundary()
    identity = _identity(boundary, tmp_path / "reviewer-home")
    marker = tmp_path / "marker"
    marker.write_bytes(b"a" * 65)

    with pytest.raises(boundary.BoundaryError, match="marker is invalid"):
        boundary._read_start_marker(marker, "a" * 64, identity)


def test_real_seatbelt_denies_child_and_grandchild_when_privileged(tmp_path):
    if sys.platform != "darwin" or os.geteuid() != 0:
        pytest.skip("requires a macOS root supervisor")
    reviewer_name = os.environ.get("CCE_ISOLATED_REVIEW_TEST_USER")
    if not reviewer_name:
        pytest.skip("requires a provisioned dedicated reviewer account")

    boundary = _load_boundary()
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "state").write_bytes(b"protected\n")
    identity = boundary.require_supervisor_and_reviewer(reviewer_name, (protected,))
    quarantine = boundary._quarantine_path(None, (protected, identity.home))
    snapshot = quarantine / "snapshot"
    snapshot.mkdir(mode=0o555)
    boundary._prepare_runtime_directories(quarantine, identity)
    environment = boundary.clean_child_environment(
        snapshot,
        quarantine,
        identity=identity,
        provider_proxy_port=None,
    )
    profile = boundary.sandbox_profile(
        (protected,), quarantine, snapshot, identity, provider_proxy_port=None
    )

    boundary._run_seatbelt_negative_control(
        boundary._sandbox_executable(),
        profile,
        identity,
        (protected,),
        snapshot,
        quarantine,
        environment,
    )


def test_snapshot_files_are_read_only_after_export(tmp_path):
    boundary = _load_boundary()
    repo = _repository(tmp_path)
    snapshot = tmp_path / "snapshot"

    boundary.export_snapshot(repo, snapshot)

    assert stat.S_IMODE(os.stat(snapshot).st_mode) == 0o555
    assert stat.S_IMODE(os.stat(snapshot / "tracked.txt").st_mode) in {0o444, 0o555}
