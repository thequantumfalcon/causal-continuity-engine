"""Regression coverage for platform-independent clocks and release artifacts."""

import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema.validators import validator_for
from referencing import Registry, Resource

import causal_continuity_engine as runtime_package
import causal_continuity_engine.capabilities as capabilities
import causal_continuity_engine.core as core
import causal_continuity_engine.engine as engine_module
import causal_continuity_engine.proof as proof_module
from causal_continuity_engine.engine import Engine
from tests.schema_validation import draft202012_validator

ROOT = Path(__file__).resolve().parent.parent
SDIST_NAME = f"causal_continuity_engine-{runtime_package.__version__}.tar.gz"
SCHEMA_PATHS = tuple(sorted((ROOT / "schemas").glob("*.json")))
SCHEMA_URI_BASE = (
    "https://raw.githubusercontent.com/thequantumfalcon/"
    "causal-continuity-engine/v0.1.0/schemas/"
)


def test_adr_inventory_is_unique_ordered_and_contiguous():
    text = (ROOT / "docs" / "adr" / "ADR-INDEX.md").read_text(
        encoding="utf-8")
    foundational = [
        int(value)
        for value in re.findall(r"^\| ADR-([0-9]{3}) \|", text, re.MULTILINE)
    ]
    headings = [
        int(value)
        for value in re.findall(r"^## ADR-([0-9]{3})\b", text, re.MULTILINE)
    ]

    assert foundational == list(range(1, 11))
    assert headings == list(range(11, headings[-1] + 1))
    inventory = foundational + headings
    assert len(inventory) == len(set(inventory))


def _load_release_script(name, root=ROOT):
    path = root / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(
        f"causal_continuity_engine_{name}_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_utcnow_orders_equal_wall_clock_samples(monkeypatch):
    """A coarse platform clock must not collapse adjacent tx boundaries."""

    frozen = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)

    class FrozenDateTime:
        @classmethod
        def now(cls, tz):
            assert tz is timezone.utc
            return frozen

    monkeypatch.setattr(core, "datetime", FrozenDateTime)
    monkeypatch.setattr(core, "_last_utcnow", None)

    first = core.utcnow()
    second = core.utcnow()

    assert first == "2026-08-02T12:00:00.000000Z"
    assert second == "2026-08-02T12:00:00.000001Z"


def test_capability_markdown_is_utf8_with_lf_on_every_platform(tmp_path, monkeypatch):
    """The generated capability gate must be byte-identical across OSes."""

    (tmp_path / "docs").mkdir()
    monkeypatch.setattr(capabilities, "ROOT", tmp_path)
    monkeypatch.setattr(capabilities, "verify", lambda: [])

    assert capabilities.main(["--write"]) == 0
    rendered = (tmp_path / "docs" / "CAPABILITIES.md").read_bytes()

    assert rendered.decode("utf-8") == capabilities.render_markdown()
    assert b"\r\n" not in rendered


def test_capability_evidence_follows_installed_distribution_record(tmp_path, monkeypatch):
    """Wheel data may use a user/target scheme unrelated to sysconfig's default."""
    installed = (tmp_path / "installed" / "share" /
                 "causal-continuity-engine" / "audit" / "SPEC.md")
    installed.parent.mkdir(parents=True)
    installed.write_text("normative", encoding="utf-8")

    class FakeDistribution:
        files = [Path("../../../share/causal-continuity-engine/audit/SPEC.md")]

        @staticmethod
        def locate_file(entry):
            assert entry == FakeDistribution.files[0]
            return installed

    empty_checkout = tmp_path / "checkout"
    empty_checkout.mkdir()
    monkeypatch.setattr(capabilities, "ROOT", empty_checkout)
    monkeypatch.setattr(capabilities, "distribution", lambda name: FakeDistribution())

    assert capabilities._evidence_exists("SPEC.md")


def test_capability_resolves_owned_verifier_without_top_level_import(
        tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    verifier = checkout / "verifiers" / "verify_proof.py"
    verifier.parent.mkdir(parents=True)
    (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    verifier.write_text(
        "def verify():\n    return 'source-audit'\n",
        encoding="utf-8")

    def sanitized_import(name):
        raise AssertionError(f"sanitized import unexpectedly tried {name}")

    monkeypatch.setattr(capabilities, "ROOT", checkout)
    monkeypatch.setattr(capabilities.importlib, "import_module", sanitized_import)

    assert capabilities._resolve("verifiers.verify_proof:verify")() == "source-audit"


def test_capability_resolves_verifier_from_owned_installed_audit_data(
        tmp_path, monkeypatch):
    installed = (tmp_path / "installed" / "share" /
                 "causal-continuity-engine" / "audit" /
                 "verifiers" / "verify_proof.py")
    installed.parent.mkdir(parents=True)
    installed.write_text(
        "def derive_fingerprint():\n    return 'installed-audit'\n",
        encoding="utf-8")

    class FakeDistribution:
        files = [Path(
            "../../../share/causal-continuity-engine/audit/"
            "verifiers/verify_proof.py")]

        @staticmethod
        def locate_file(entry):
            assert entry == FakeDistribution.files[0]
            return installed

    empty_checkout = tmp_path / "checkout"
    empty_checkout.mkdir()
    monkeypatch.setattr(capabilities, "ROOT", empty_checkout)
    monkeypatch.setattr(capabilities, "distribution", lambda name: FakeDistribution())

    resolved = capabilities._resolve(
        "verifiers.verify_proof:derive_fingerprint")
    assert resolved() == "installed-audit"


def test_capability_checkout_cannot_borrow_stale_installed_evidence(
        tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    class StaleDistribution:
        files = [Path("../../../SPEC.md")]

        @staticmethod
        def locate_file(entry):
            raise AssertionError("a checkout must never consult another installation")

    monkeypatch.setattr(capabilities, "ROOT", checkout)
    monkeypatch.setattr(capabilities, "distribution", lambda name: StaleDistribution())

    assert not capabilities._evidence_exists("SPEC.md")


@pytest.mark.parametrize("schema_path", SCHEMA_PATHS,
                         ids=lambda path: path.name)
def test_shipped_schema_passes_its_declared_metaschema(schema_path):
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator_for(schema).check_schema(schema)


def test_public_schema_documents_are_unambiguous_json():
    """No duplicate member may be silently discarded before schema checking."""
    for schema_path in SCHEMA_PATHS:
        parsed = core.strict_json_loads(
            schema_path.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict), schema_path.name


def test_public_schema_inventory_exactly_matches_shipped_contracts():
    assert runtime_package.SCHEMA_VERSIONS == {
        "anchor": "cce.anchor.v1",
        "recovery_packet": "cce.recovery.v1",
        "event": "cce.event.v1",
        "resume_packet": "cce.resume.v1",
        "proof": "cce.proof.v1",
        "proof_predicate": "cce.proof-predicate.v1",
        "capsule": "cce.capsule.v1",
        "continuity_receipt": "cce.continuity-receipt.v1",
    }
    assert set(runtime_package.SCHEMA_VERSIONS.values()) == {
        path.name.removesuffix(".json") for path in SCHEMA_PATHS
    }


def test_schema_ids_are_release_tagged_and_runtime_has_no_legacy_type_uri():
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in SCHEMA_PATHS
    }

    assert len(schemas) == len(runtime_package.SCHEMA_VERSIONS)
    assert {
        name: schema["$id"] for name, schema in schemas.items()
    } == {
        name: SCHEMA_URI_BASE + name for name in schemas
    }
    legacy_host = "https://cce" + ".dev/"
    shipped_contract_files = [
        *SCHEMA_PATHS,
        *(ROOT / "causal_continuity_engine").glob("*.py"),
    ]
    assert not {
        path.relative_to(ROOT).as_posix()
        for path in shipped_contract_files
        if legacy_host in path.read_text(encoding="utf-8")
    }


def test_capsule_external_refs_are_release_tagged_schema_ids():
    capsule = json.loads(
        (ROOT / "schemas" / "cce.capsule.v1.json").read_text(encoding="utf-8"))

    refs = set()

    def collect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref" and isinstance(child, str):
                    refs.add(child)
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(capsule)
    assert {ref for ref in refs if not ref.startswith("#")} == {
        SCHEMA_URI_BASE + "cce.resume.v1.json",
        SCHEMA_URI_BASE + "cce.resume.v1.json#/$defs/signature",
    }


def test_runtime_type_uris_equal_their_release_tagged_schema_ids():
    predicate_schema = json.loads(
        (ROOT / "schemas" / "cce.proof-predicate.v1.json").read_text(
            encoding="utf-8"))
    receipt_schema = json.loads(
        (ROOT / "schemas" / "cce.continuity-receipt.v1.json").read_text(
            encoding="utf-8"))

    assert proof_module.PREDICATE_TYPE == predicate_schema["$id"]
    assert engine_module._CONTINUITY_PAYLOAD_TYPE == receipt_schema["$id"]
    assert (
        receipt_schema["properties"]["payload_type"]["const"]
        == receipt_schema["$id"]
    )


def test_intoto_predicate_validates_with_resolved_proof_schema():
    proof_schema = json.loads(
        (ROOT / "schemas" / "cce.proof.v1.json").read_text(encoding="utf-8"))
    predicate_schema = json.loads(
        (ROOT / "schemas" / "cce.proof-predicate.v1.json").read_text(
            encoding="utf-8"))
    vector = json.loads(
        (ROOT / "vectors" / "valid_hmac.json").read_text(encoding="utf-8"))
    statement = proof_module.to_intoto(vector["envelope"])
    registry = Registry().with_resource(
        proof_schema["$id"], Resource.from_contents(proof_schema))

    assert statement["predicateType"] == predicate_schema["$id"]
    draft202012_validator(
        predicate_schema, registry=registry).validate(statement["predicate"])


def test_emitted_continuity_receipt_matches_closed_world_schema(tmp_path):
    schema = json.loads(
        (ROOT / "schemas" / "cce.continuity-receipt.v1.json").read_text(
            encoding="utf-8"))
    validator = draft202012_validator(schema)

    engine = Engine(workdir=tmp_path)
    try:
        project_id = "prj_receipt_schema"
        engine.create_project("receipt-schema", project_id=project_id)
        receipt = engine.continuity_check(project_id)["continuity_receipt"]
        validator.validate(receipt)
    finally:
        engine.close()


def _reseal_receipt(engine, receipt):
    receipt["receipt_digest"] = core.digest_obj({
        key: value for key, value in receipt.items()
        if key not in ("signature", "receipt_digest")
    })
    receipt["signature"] = engine.signer.sign(receipt)
    return receipt


@pytest.mark.parametrize(
    "timestamp",
    [
        "20260804T123456Z",
        "2026-08-04 12:34:56.123456Z",
        "2026-02-30T12:34:56.123456Z",
        "2026-08-04T12:34:56Z",
    ],
)
def test_resigned_continuity_receipt_rejects_noncanonical_time(
        tmp_path, timestamp):
    schema = json.loads(
        (ROOT / "schemas" / "cce.continuity-receipt.v1.json").read_text(
            encoding="utf-8"))
    validator = draft202012_validator(schema)
    engine = Engine(tmp_path / "receipt.db", workdir=tmp_path)
    try:
        project_id = "prj_receipt_time"
        engine.create_project("receipt-time", project_id=project_id)
        receipt = engine.continuity_check(project_id)["continuity_receipt"]
        receipt["generated_at"] = timestamp
        _reseal_receipt(engine, receipt)

        assert list(validator.iter_errors(receipt))
        result = engine.verify_continuity_receipt(project_id, receipt)
        assert result["verdict"] == "INVALID"
    finally:
        engine.close()


@pytest.mark.parametrize(
    "invalid",
    [None, "", 0, False, [], {}, "not-a-digest"],
)
@pytest.mark.parametrize(
    "field",
    ["policy_digest", "projection_digest", "entries_digest"],
)
def test_resigned_receipt_rejects_malformed_basis_digests(
        tmp_path, field, invalid):
    engine = Engine(tmp_path / "receipt-digest.db", workdir=tmp_path)
    try:
        project_id = "prj_receipt_digest"
        engine.create_project("receipt-digest", project_id=project_id)
        receipt = engine.continuity_check(project_id)["continuity_receipt"]
        if field == "entries_digest":
            receipt["basis"]["project_event_frontier"][field] = invalid
        else:
            receipt["basis"][field] = invalid
        _reseal_receipt(engine, receipt)

        result = engine.verify_continuity_receipt(project_id, receipt)
        assert result["verdict"] == "INVALID"
    finally:
        engine.close()


def test_receipt_digest_shape_keeps_current_and_historical_distinct(tmp_path):
    engine = Engine(tmp_path / "receipt-control.db", workdir=tmp_path)
    try:
        project_id = "prj_receipt_control"
        engine.create_project("receipt-control", project_id=project_id)
        current = engine.continuity_check(project_id)["continuity_receipt"]
        assert engine.verify_continuity_receipt(
            project_id, current)["verdict"] == "CURRENT"

        historical = copy.deepcopy(current)
        historical["basis"]["policy_digest"] = "sha256:" + "0" * 64
        _reseal_receipt(engine, historical)
        assert engine.verify_continuity_receipt(
            project_id, historical)["verdict"] == "AUTHENTIC_HISTORICAL"
    finally:
        engine.close()


def test_emitted_anchor_and_recovery_match_published_schemas(tmp_path):
    anchor_schema = json.loads(
        (ROOT / "schemas" / "cce.anchor.v1.json").read_text(encoding="utf-8"))
    recovery_schema = json.loads(
        (ROOT / "schemas" / "cce.recovery.v1.json").read_text(encoding="utf-8"))
    anchor_validator = draft202012_validator(anchor_schema)
    recovery_validator = draft202012_validator(recovery_schema)
    engine = Engine(tmp_path / "inventory.db", workdir=tmp_path)
    try:
        project_id = "prj_public_inventory"
        engine.create_project("public-inventory", project_id=project_id)
        engine.memory.checkpoint(
            tenant_id=engine.tenant_id, project_id=project_id,
            session_id=None, label="safe", working_state={"step": 1},
            verified=True)
        engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id,
            project_id=project_id, status="open",
            data={"title": "finish release"})
        engine.graph.put_node(
            entity_type="artifact", tenant_id=engine.tenant_id,
            project_id=project_id, status="verified",
            data={"title": "validated wheel"})
        engine.partial.record_outcome(
            tenant_id=engine.tenant_id, project_id=project_id,
            session_id=None, status="partially_completed",
            completed=[{"name": "build"}],
            failed=[{"name": "publish"}],
            blocked=[{"name": "approval"}],
            skipped=[{"name": "mirror"}],
            unverified=[{"name": "download"}],
            failure_mode="tool")
        anchor = engine.store.export_anchor(
            "events", tenant_id=engine.tenant_id, project_id=project_id)
        recovery = engine.partial.recovery_packet(project_id)
        anchor_validator.validate(anchor)
        recovery_validator.validate(recovery)

        malformed_anchor = copy.deepcopy(anchor)
        malformed_anchor["unknown"] = True
        assert list(anchor_validator.iter_errors(malformed_anchor))
        malformed_recovery = copy.deepcopy(recovery)
        malformed_recovery["generated_at"] = "2026-02-30T00:00:00.000000Z"
        assert list(recovery_validator.iter_errors(malformed_recovery))
    finally:
        engine.close()


def test_emitted_capsule_matches_closed_field_level_schema(tmp_path):
    resume_schema = json.loads(
        (ROOT / "schemas" / "cce.resume.v1.json").read_text(
            encoding="utf-8"))
    capsule_schema = json.loads(
        (ROOT / "schemas" / "cce.capsule.v1.json").read_text(
            encoding="utf-8"))
    registry = Registry().with_resource(
        resume_schema["$id"], Resource.from_contents(resume_schema))
    validator = draft202012_validator(
        capsule_schema, registry=registry)

    engine = Engine(tmp_path / "capsule.db", workdir=tmp_path)
    try:
        project_id = "prj_capsule_schema"
        engine.create_project("capsule-schema", project_id=project_id)
        capsule = engine.capsules.export(
            tenant_id=engine.tenant_id, project_id=project_id,
            session_id=None, source_model="source",
            source_runtime="runtime", target_adapter="target",
            signer=engine.signer)
        validator.validate(capsule)

        malformed = copy.deepcopy(capsule)
        malformed["source"]["unsigned_interpretation"] = "trusted"
        assert list(validator.iter_errors(malformed))

        malformed = copy.deepcopy(capsule)
        malformed["resume_packet"]["environment"] = 1
        assert list(validator.iter_errors(malformed))
    finally:
        engine.close()


def test_release_checksum_manifest_cannot_describe_stale_bytes(tmp_path):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "causal_continuity_engine.whl"
    sdist = tmp_path / "causal_continuity_engine.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    artifacts = [wheel, sdist]
    manifest = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(artifacts, key=lambda item: item.name))
    (tmp_path / "SHA256SUMS").write_text(manifest, encoding="ascii", newline="\n")

    verifier._verify_checksums(tmp_path, artifacts)
    wheel.write_bytes(b"substituted wheel")
    with pytest.raises(SystemExit, match="does not exactly describe"):
        verifier._verify_checksums(tmp_path, artifacts)


def test_distribution_verifier_rejects_every_unpublished_extra(tmp_path):
    verifier = _load_release_script("verify_distributions")
    (tmp_path / "causal_continuity_engine.whl").write_bytes(b"wheel")
    (tmp_path / "causal_continuity_engine.tar.gz").write_bytes(b"sdist")
    (tmp_path / "SHA256SUMS").write_text("", encoding="ascii")
    (tmp_path / "debug.log").write_text("not a release asset", encoding="utf-8")

    with pytest.raises(SystemExit, match="unexpected release assets: debug.log"):
        verifier._release_assets(tmp_path)


def _write_sdist_members(
        path, members, *, member_mutator=None,
        archive_format=tarfile.USTAR_FORMAT, epoch=0):
    with tarfile.open(path, "w:gz", format=archive_format) as archive:
        for name, member_type, body, linkname in members:
            member = tarfile.TarInfo(name)
            member.type = member_type
            member.linkname = linkname
            executable = "/.githooks/" in name or name.endswith(".sh")
            member.mode = 0o755 if (
                member_type == tarfile.DIRTYPE or executable) else 0o644
            member.mtime = epoch
            member.size = len(body) if member_type == tarfile.REGTYPE else 0
            if member_mutator is not None:
                member_mutator(member)
            archive.addfile(
                member,
                io.BytesIO(body) if member_type == tarfile.REGTYPE else None,
            )


def _sdist_contract_fixture(
        tmp_path, verifier, *, omit=(), replacements=None, extras=None):
    source_payload = verifier._expected_sdist_source_payload(ROOT)
    project, project_version = verifier._project_contract(ROOT)
    project_name = project["project"]["name"]
    archive_root = (
        f"{verifier._distribution_filename_stem(project_name)}-{project_version}")
    dist_root = f"{archive_root}.dist-info"

    dev_metadata = "".join(
        f'Requires-Dist: {requirement}; extra == "dev"\n'
        for requirement in project["project"]["optional-dependencies"]["dev"])
    metadata = (
        "Metadata-Version: 2.4\n"
        f"Name: {project_name}\n"
        f"Version: {project_version}\n"
        f"Requires-Python: {project['project']['requires-python']}\n"
        "Provides-Extra: dev\n"
        f"{dev_metadata}\n"
    ).encode("utf-8")
    entry_points = verifier.ENTRY_POINTS_BYTES
    top_level = verifier.TOP_LEVEL_BYTES
    expected_sources = set(source_payload) | {
        name for name in verifier.SDIST_GENERATED_FILES
        if name.startswith(verifier.EGG_INFO + "/")
    }
    generated = {
        "PKG-INFO": metadata,
        "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
        f"{verifier.EGG_INFO}/PKG-INFO": metadata,
        f"{verifier.EGG_INFO}/SOURCES.txt": (
            "".join(f"{name}\n" for name in sorted(expected_sources)).encode("utf-8")
        ),
        f"{verifier.EGG_INFO}/dependency_links.txt": b"\n",
        f"{verifier.EGG_INFO}/entry_points.txt": entry_points,
        f"{verifier.EGG_INFO}/requires.txt": (
            "\n[dev]\n"
            + "\n".join(project["project"]["optional-dependencies"]["dev"])
            + "\n"
        ).encode("utf-8"),
        f"{verifier.EGG_INFO}/top_level.txt": top_level,
    }
    payload = {**source_payload, **generated}
    for name in omit:
        payload.pop(name)
    payload.update(replacements or {})
    payload.update(extras or {})

    expected_files = set(source_payload) | verifier.SDIST_GENERATED_FILES
    directories = verifier._sdist_expected_directories(expected_files)
    descendants = [
        (f"{archive_root}/{name}", tarfile.DIRTYPE, b"", "")
        for name in sorted(directories)
    ]
    descendants.extend(
        (f"{archive_root}/{name}", tarfile.REGTYPE, body, "")
        for name, body in sorted(payload.items())
    )
    members = [(archive_root, tarfile.DIRTYPE, b"", "")]
    members.extend(sorted(descendants, key=lambda item: item[0]))
    sdist = tmp_path / f"{archive_root}.tar.gz"
    _write_sdist_members(sdist, members)

    wheel = tmp_path / f"{archive_root}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{dist_root}/METADATA", metadata)
        archive.writestr(f"{dist_root}/entry_points.txt", entry_points)
        archive.writestr(f"{dist_root}/top_level.txt", top_level)
    return sdist, wheel


def _verify_sdist_fixture(verifier, sdist, wheel):
    with tarfile.open(sdist, "r:gz") as source_archive, \
            zipfile.ZipFile(wheel) as wheel_archive:
        verifier._verify_sdist_contract(source_archive, wheel_archive, ROOT)


def test_distribution_verifier_accepts_exact_sdist_contract(tmp_path):
    verifier = _load_release_script("verify_distributions")
    sdist, wheel = _sdist_contract_fixture(tmp_path, verifier)

    _verify_sdist_fixture(verifier, sdist, wheel)


def _minimal_indexed_source_tree(tmp_path, verifier):
    root = tmp_path / "indexed-source"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    required = (
        verifier.SDIST_ROOT_FILES
        | verifier.GITHUB_ROOT_FILES
        | verifier.GITHOOK_FILES
    )
    for relative in sorted(required):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (
            "*.db\n.cce/\nprivate.py\nprivate.yml\n*.ignore\n"
            "/build/\n*.egg-info/\n"
        ) \
            if relative == ".gitignore" else f"owned: {relative}\n"
        path.write_text(body, encoding="utf-8", newline="\n")
    tree_examples = {
        "benchmarks/owned.py",
        "causal_continuity_engine/owned.py",
        "docs/owned.md",
        "examples/owned.py",
        "schemas/owned.json",
        "tests/owned.py",
        "vectors/owned.py",
        "verifiers/owned.py",
        ".github/ISSUE_TEMPLATE/owned.yml",
        ".github/scripts/owned.py",
        ".github/workflows/owned.yml",
    }
    for relative in sorted(tree_examples):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"owned: {relative}\n", encoding="utf-8", newline="\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git", "update-index", "--chmod=+x", "--",
            ".githooks/commit-msg", ".githooks/pre-commit",
        ],
        cwd=root, check=True)
    return root


def test_source_inventory_ignores_debris_but_accepts_safe_new_source(
        tmp_path):
    verifier = _load_release_script("verify_distributions")
    root = _minimal_indexed_source_tree(tmp_path, verifier)
    ignored = {
        ".github/private.db": b"private database",
        ".github/scripts/nested/.cce/secret.py": b"SECRET = True\n",
        ".github/workflows/private.yml": b"secret: true\n",
        "tests/arbitrary.ignore": b"ignored debris",
        "tests/private.py": b"SECRET = True\n",
        "build/lib/cce/api.py": b"OBSOLETE = True\n",
        "causal_continuity_engine.egg-info/SOURCES.txt": b"stale ledger\n",
    }
    for relative, body in ignored.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    safe_new = root / "tests" / "test_new_behavior.py"
    safe_new.write_text("def test_new_behavior(): pass\n", encoding="utf-8")

    payload = verifier._expected_sdist_source_payload(root)

    assert set(ignored).isdisjoint(payload)
    assert "tests/test_new_behavior.py" in payload
    with pytest.raises(
            SystemExit, match=r"untracked files: tests/test_new_behavior\.py"):
        verifier._require_exact_git_source(root)
    (root / "release-notes.tmp").write_text("not reviewed\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="outside the shipped allowlist.*release-notes.tmp"):
        verifier._expected_sdist_source_payload(root)


@pytest.mark.parametrize(
    "names",
    [
        ["Dir/a.txt", "dir/b.txt"],
        ["Dir", "dir/child.txt"],
        ["bad?.txt"],
    ],
    ids=("directory-prefix-case-alias", "file-parent-case-alias",
         "windows-forbidden-character"),
)
def test_source_inventory_rejects_nonportable_path_sets(names):
    verifier = _load_release_script("verify_distributions")

    with pytest.raises(SystemExit, match="cross-platform|unsafe archive path"):
        verifier._validated_source_names(names, label="planted source inventory")


def test_exact_release_source_rejects_eol_bytes_hidden_by_git_normalization(
        tmp_path):
    verifier = _load_release_script("verify_distributions")
    root = _minimal_indexed_source_tree(tmp_path, verifier)
    (root / ".gitattributes").write_text(
        "* text=auto\n", encoding="utf-8", newline="\n")
    subprocess.run(
        ["git", "config", "core.autocrlf", "true"], cwd=root, check=True)
    # Only the attributes file changed. A broad restage would recalculate the
    # synthetic executable hook modes on POSIX and invalidate the fixture
    # before the physical-byte check under test.
    subprocess.run(
        ["git", "add", "--", ".gitattributes"], cwd=root, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Release Test",
            "-c", "user.email=release@example.invalid",
            "commit", "-qm", "test: exact source fixture",
        ],
        cwd=root, check=True)
    readme = root / "README.md"
    readme.unlink()
    subprocess.run(["git", "checkout", "--", "README.md"], cwd=root, check=True)

    assert b"\r\n" in readme.read_bytes()
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--", "README.md"],
        cwd=root, text=True)
    assert status == ""
    with pytest.raises(SystemExit, match=r"physical source bytes differ.*README\.md"):
        verifier._require_exact_git_source(root)


def test_manifest_has_no_broad_github_or_hook_recursion():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "recursive-include .github *" not in manifest
    assert "recursive-include .githooks *" not in manifest
    assert "recursive-include .github/scripts *.py" in manifest
    assert "include .githooks/commit-msg .githooks/pre-commit" in manifest


@pytest.mark.parametrize(
    "extra_name",
    [
        ".github/workflows/private.yml",
        "build/lib/cce/api.py",
        "cce/__init__.py",
    ],
)
def test_sdist_contract_rejects_backend_selected_ignored_member(
        tmp_path, extra_name):
    verifier = _load_release_script("verify_distributions")
    sdist, wheel = _sdist_contract_fixture(
        tmp_path, verifier,
        extras={extra_name: b"stale or private payload\n"})

    with pytest.raises(SystemExit, match="unexpected:"):
        _verify_sdist_fixture(verifier, sdist, wheel)


@pytest.mark.parametrize(
    "mutation, diagnostic",
    [
        (
            {"omit": {"causal_continuity_engine/api.py"}},
            r"missing: causal_continuity_engine/api\.py",
        ),
        (
            {"replacements": {"causal_continuity_engine/api.py": b"SUBSTITUTED = True\n"}},
            r"source bytes differ.*causal_continuity_engine/api\.py",
        ),
        (
            {"omit": {"docs/assets/social-preview.png"}},
            r"missing: docs/assets/social-preview\.png",
        ),
        ({"extras": {"setup.py": b"raise SystemExit('unexpected')\n"}},
         r"unexpected: setup\.py"),
    ],
    ids=("omitted", "altered", "social-preview-omitted", "extra"),
)
def test_distribution_verifier_rejects_sdist_source_divergence(
        tmp_path, mutation, diagnostic):
    verifier = _load_release_script("verify_distributions")
    sdist, wheel = _sdist_contract_fixture(tmp_path, verifier, **mutation)

    with pytest.raises(SystemExit, match=diagnostic):
        _verify_sdist_fixture(verifier, sdist, wheel)


@pytest.mark.parametrize(
    "names, diagnostic",
    [
        (["causal_continuity_engine-0.1.0/../escape.py"], "unsafe archive path"),
        (["causal_continuity_engine-0.1.0/NUL.txt"], "unsafe archive path"),
        (
            [
                "causal_continuity_engine-0.1.0/"
                "causal_continuity_engine/api.py",
                "causal_continuity_engine-0.1.0/"
                "CAUSAL_CONTINUITY_ENGINE/API.PY",
            ],
            "collide cross-platform",
        ),
        (
            [
                "causal_continuity_engine-0.1.0/Dir/a.py",
                "causal_continuity_engine-0.1.0/dir/b.py",
            ],
            "directory prefixes collide cross-platform",
        ),
        (
            [
                "causal_continuity_engine-0.1.0/Dir",
                "causal_continuity_engine-0.1.0/dir/child.py",
            ],
            "file/directory paths collide cross-platform",
        ),
    ],
    ids=(
        "traversal",
        "reserved-name",
        "case-collision",
        "directory-prefix-case-collision",
        "file-directory-collision",
    ),
)
def test_distribution_verifier_rejects_unsafe_sdist_paths(
        tmp_path, names, diagnostic):
    verifier = _load_release_script("verify_distributions")
    sdist = tmp_path / "unsafe.tar.gz"
    members = [("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", "")]
    members.extend((name, tarfile.REGTYPE, b"payload", "") for name in names)
    _write_sdist_members(sdist, members)

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match=diagnostic):
            verifier._sdist_member_map(archive, "causal_continuity_engine-0.1.0")


def test_distribution_verifier_rejects_duplicate_sdist_member(tmp_path):
    verifier = _load_release_script("verify_distributions")
    sdist = tmp_path / "duplicate.tar.gz"
    duplicate = "causal_continuity_engine-0.1.0/causal_continuity_engine/api.py"
    _write_sdist_members(sdist, [
        ("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", ""),
        (duplicate, tarfile.REGTYPE, b"first", ""),
        (duplicate, tarfile.REGTYPE, b"second", ""),
    ])

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match="duplicate archive entries"):
            verifier._sdist_member_map(archive, "causal_continuity_engine-0.1.0")


@pytest.mark.parametrize(
    "member_type, linkname",
    [
        (tarfile.SYMTYPE, "../../outside"),
        (tarfile.LNKTYPE, "causal_continuity_engine-0.1.0/causal_continuity_engine/api.py"),
        (tarfile.FIFOTYPE, ""),
    ],
    ids=("symlink", "hardlink", "fifo"),
)
def test_distribution_verifier_rejects_non_regular_sdist_members(
        tmp_path, member_type, linkname):
    verifier = _load_release_script("verify_distributions")
    sdist = tmp_path / "special.tar.gz"
    _write_sdist_members(sdist, [
        ("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", ""),
        (
            "causal_continuity_engine-0.1.0/"
            "causal_continuity_engine/api.py",
            member_type,
            b"",
            linkname,
        ),
    ])

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match="non-regular archive member"):
            verifier._sdist_member_map(archive, "causal_continuity_engine-0.1.0")


@pytest.mark.parametrize(
    "replacement, diagnostic",
    [
        (
            {"causal_continuity_engine.egg-info/SOURCES.txt": b"causal_continuity_engine/api.py\n"},
            "SOURCES.txt does not exactly ledger",
        ),
        (
            {"PKG-INFO": b"Metadata-Version: 2.4\nName: substituted\n\n"},
            "root and egg-info PKG-INFO are not byte-identical",
        ),
    ],
    ids=("generated-ledger", "generated-metadata"),
)
def test_distribution_verifier_rejects_sdist_generated_contract_mismatch(
        tmp_path, replacement, diagnostic):
    verifier = _load_release_script("verify_distributions")
    sdist, wheel = _sdist_contract_fixture(
        tmp_path, verifier, replacements=replacement)

    with pytest.raises(SystemExit, match=diagnostic):
        _verify_sdist_fixture(verifier, sdist, wheel)


def test_wheel_build_runs_only_after_normalized_sdist_validation(
        tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    calls = []

    def backend(distribution, source, output, environment):
        del environment
        calls.append(f"backend:{distribution}")
        if distribution == "sdist":
            assert source != builder.ROOT
            assert (source / "pyproject.toml").read_bytes() == b"isolated source\n"
            (output / "causal_continuity_engine-0.1.0.tar.gz").write_bytes(b"backend-sdist")
        else:
            with zipfile.ZipFile(output / "causal_continuity_engine-0.1.0-py3-none-any.whl", "w"):
                pass

    class Verifier:
        @staticmethod
        def _require_exact_git_source(source_root):
            del source_root

        @staticmethod
        def _expected_sdist_source_payload(source_root):
            del source_root
            calls.append("preflight-inventory")
            return {"pyproject.toml": b"isolated source\n"}

        @staticmethod
        def _require_source_payload_matches_git_index(source_root, payload):
            del source_root
            assert payload == {"pyproject.toml": b"isolated source\n"}
            calls.append("bind-captured-source")

        @staticmethod
        def _validated_source_names(names, *, label):
            del label
            return set(names)

        @staticmethod
        def _extract_validated_sdist(path, destination, source_root, **kwargs):
            del path, source_root, kwargs
            calls.append("validate-and-extract")
            extracted = destination / "causal_continuity_engine-0.1.0"
            extracted.mkdir()
            return extracted

        @staticmethod
        def _validated_sdist_payload(path, source_root, **kwargs):
            del path, source_root, kwargs
            calls.append("validate-pair")

    monkeypatch.setattr(builder, "_source_snapshot", lambda *args: {})
    monkeypatch.setattr(builder, "_run_backend", backend)
    monkeypatch.setattr(
        builder, "_normalize_sdist", lambda path, epoch: calls.append("normalize"))
    monkeypatch.setattr(builder, "_normalize_wheel", lambda path, epoch: None)
    monkeypatch.setattr(builder, "_release_verifier", lambda: Verifier)

    builder._build(tmp_path, "1700000000")

    assert calls == [
        "preflight-inventory", "bind-captured-source", "backend:sdist",
        "normalize", "validate-and-extract", "backend:wheel", "validate-pair",
    ]


def test_unsafe_sdist_prevents_wheel_backend_execution(tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    backend_calls = []

    def backend(distribution, source, output, environment):
        del source, environment
        backend_calls.append(distribution)
        (output / "causal_continuity_engine-0.1.0.tar.gz").write_bytes(b"unsafe")

    class RejectingVerifier:
        @staticmethod
        def _require_exact_git_source(source_root):
            del source_root

        @staticmethod
        def _expected_sdist_source_payload(source_root):
            del source_root
            return {}

        @staticmethod
        def _require_source_payload_matches_git_index(source_root, payload):
            del source_root, payload

        @staticmethod
        def _validated_source_names(names, *, label):
            del label
            return set(names)

        @staticmethod
        def _extract_validated_sdist(*args, **kwargs):
            raise SystemExit("sdist contains unsafe archive path")

    monkeypatch.setattr(builder, "_source_snapshot", lambda *args: {})
    monkeypatch.setattr(builder, "_run_backend", backend)
    monkeypatch.setattr(builder, "_normalize_sdist", lambda path, epoch: None)
    monkeypatch.setattr(builder, "_release_verifier", lambda: RejectingVerifier)

    with pytest.raises(SystemExit, match="unsafe archive path"):
        builder._build(tmp_path, "1700000000")

    assert backend_calls == ["sdist"]
    assert list(tmp_path.iterdir()) == []


def test_unsafe_source_inventory_prevents_any_backend_execution(
        tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    backend_calls = []

    class RejectingVerifier:
        @staticmethod
        def _require_exact_git_source(source_root):
            del source_root

        @staticmethod
        def _expected_sdist_source_payload(source_root):
            del source_root
            raise SystemExit("source inventory contains files outside the shipped allowlist")

    monkeypatch.setattr(
        builder, "_run_backend",
        lambda *args, **kwargs: backend_calls.append((args, kwargs)))
    monkeypatch.setattr(builder, "_release_verifier", lambda: RejectingVerifier)

    with pytest.raises(SystemExit, match="outside the shipped allowlist"):
        builder._build(tmp_path, "1700000000")

    assert backend_calls == []


@pytest.mark.parametrize(
    "mutation, diagnostic, archive_format",
    [
        (lambda member: setattr(member, "uid", 7), "ownership headers", tarfile.USTAR_FORMAT),
        (lambda member: setattr(member, "mtime", 124), "mtime differs", tarfile.USTAR_FORMAT),
        (
            lambda member: setattr(member, "mode", 0o600),
            "mode is not canonical", tarfile.USTAR_FORMAT,
        ),
        (
            lambda member: setattr(
                member, "pax_headers", {"comment": "x"}),
            "PAX headers", tarfile.PAX_FORMAT,
        ),
        (
            lambda member: setattr(member, "linkname", "phantom"),
            "link fields", tarfile.USTAR_FORMAT,
        ),
    ],
    ids=("owner", "mtime", "mode", "pax", "link-field"),
)
def test_distribution_verifier_rejects_noncanonical_sdist_headers(
        tmp_path, mutation, diagnostic, archive_format):
    verifier = _load_release_script("verify_distributions")

    def mutate_file(member):
        if member.type == tarfile.REGTYPE:
            mutation(member)

    sdist = tmp_path / "headers.tar.gz"
    _write_sdist_members(
        sdist,
        [
            ("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", ""),
            (
                "causal_continuity_engine-0.1.0/causal_continuity_engine.py",
                tarfile.REGTYPE,
                b"pass\n",
                "",
            ),
        ],
        member_mutator=mutate_file, archive_format=archive_format, epoch=123)

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match=diagnostic):
            verifier._sdist_member_map(
                archive, "causal_continuity_engine-0.1.0", expected_epoch=123)


def test_distribution_verifier_rejects_device_fields_on_regular_member():
    verifier = _load_release_script("verify_distributions")
    root = tarfile.TarInfo("causal_continuity_engine-0.1.0")
    root.type = tarfile.DIRTYPE
    root.mode = 0o755
    regular = tarfile.TarInfo("causal_continuity_engine-0.1.0/causal_continuity_engine.py")
    regular.type = tarfile.REGTYPE
    regular.mode = 0o644
    regular.devmajor = 9

    class HeaderArchive:
        pax_headers = {}

        @staticmethod
        def __iter__():
            return iter((root, regular))

    with pytest.raises(SystemExit, match="device fields"):
        verifier._sdist_member_map(HeaderArchive(), "causal_continuity_engine-0.1.0")


def test_distribution_verifier_rejects_noncanonical_sdist_order(tmp_path):
    verifier = _load_release_script("verify_distributions")
    sdist = tmp_path / "order.tar.gz"
    _write_sdist_members(sdist, [
        ("causal_continuity_engine-0.1.0/z.py", tarfile.REGTYPE, b"z\n", ""),
        ("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", ""),
    ])

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match="canonical lexical order"):
            verifier._sdist_member_map(archive, "causal_continuity_engine-0.1.0")


def test_distribution_verifier_bounds_sdist_member_size(tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    monkeypatch.setattr(verifier, "MAX_SDIST_MEMBER_BYTES", 4)
    sdist = tmp_path / "large-member.tar.gz"
    _write_sdist_members(sdist, [
        ("causal_continuity_engine-0.1.0", tarfile.DIRTYPE, b"", ""),
        (
            "causal_continuity_engine-0.1.0/causal_continuity_engine.py",
            tarfile.REGTYPE,
            b"12345",
            "",
        ),
    ])

    with tarfile.open(sdist, "r:gz") as archive:
        with pytest.raises(SystemExit, match="member exceeds the size limit"):
            verifier._sdist_member_map(archive, "causal_continuity_engine-0.1.0")


def test_distribution_verifier_requires_exact_sdist_filename(tmp_path):
    verifier = _load_release_script("verify_distributions")
    wrong = tmp_path / "causal_continuity_engine-substituted.tar.gz"
    wrong.write_bytes(b"not-empty")

    with pytest.raises(
            SystemExit,
            match=re.escape(
                "filename must be exactly causal_continuity_engine-"
                f"{runtime_package.__version__}.tar.gz")):
        verifier._validated_sdist_payload(wrong, ROOT, expected_epoch=1700000000)


def test_distribution_verifier_bounds_compressed_sdist_size(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    monkeypatch.setattr(verifier, "MAX_SDIST_ARCHIVE_BYTES", 9)
    sdist = tmp_path / SDIST_NAME
    sdist.write_bytes(b"0123456789")

    with pytest.raises(SystemExit, match="compressed archive exceeds"):
        verifier._validated_sdist_payload(
            sdist, ROOT, expected_epoch=1700000000)


@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
@pytest.mark.parametrize("offset, value", [(3, 4), (4, 1), (8, 0), (9, 0)])
def test_distribution_verifier_rejects_noncanonical_gzip_header(
        tmp_path, offset, value, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    epoch = 1700000000
    header = bytearray(b"\x1f\x8b\x08\x00")
    header.extend(epoch.to_bytes(4, "little"))
    header.extend(b"\x02\xff")
    header[offset] = value
    sdist = tmp_path / SDIST_NAME
    sdist.write_bytes(bytes(header) + b"payload")

    with pytest.raises(SystemExit, match="gzip header is not canonical"):
        verifier._validated_sdist_payload(
            sdist, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


def _gzip_payload(payload, epoch, *, compresslevel=9):
    rendered = io.BytesIO()
    with gzip.GzipFile(
            filename="", mode="wb", fileobj=rendered, mtime=epoch,
            compresslevel=compresslevel) as archive:
        archive.write(payload)
    return rendered.getvalue()


def _canonical_sdist_fixture(tmp_path, verifier):
    sdist, wheel = _sdist_contract_fixture(tmp_path, verifier)
    project, version = verifier._project_contract(ROOT)
    root = (
        f"{verifier._distribution_filename_stem(project['project']['name'])}-"
        f"{version}")
    with tarfile.open(sdist, "r:gz") as archive:
        members = verifier._sdist_member_map(archive, root)
        directories = {
            name for name, member in members.items()
            if name and member.isdir()
        }
        payload = {
            name: verifier._sdist_file_bytes(archive, member)
            for name, member in members.items() if member.isfile()
        }
    epoch = verifier._commit_epoch(ROOT)
    raw_tar = verifier._canonical_ustar_bytes(
        root, directories, payload, epoch)
    sdist.write_bytes(_gzip_payload(raw_tar, epoch))
    return sdist, wheel, epoch, raw_tar


@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
@pytest.mark.parametrize("tail_kind", ["raw", "concatenated-gzip"])
def test_distribution_verifier_rejects_data_after_single_gzip_stream(
        tmp_path, tail_kind, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    sdist, _, epoch, _ = _canonical_sdist_fixture(tmp_path, verifier)
    tail = b"unmodeled-tail"
    if tail_kind == "concatenated-gzip":
        tail = _gzip_payload(b"second-stream", epoch)
    sdist.write_bytes(sdist.read_bytes() + tail)

    with pytest.raises(SystemExit, match="exactly one gzip stream and no tail"):
        verifier._validated_sdist_payload(
            sdist, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
def test_distribution_verifier_rejects_extra_tar_zero_blocks(
        tmp_path, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    sdist, _, epoch, raw_tar = _canonical_sdist_fixture(tmp_path, verifier)
    sdist.write_bytes(_gzip_payload(raw_tar + (b"\0" * 10240), epoch))

    with pytest.raises(SystemExit, match="raw USTAR envelope is not canonical"):
        verifier._validated_sdist_payload(
            sdist, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


def test_distribution_verifier_rejects_alternate_deflate_encoding(tmp_path):
    verifier = _load_release_script("verify_distributions")
    sdist, _, epoch, raw_tar = _canonical_sdist_fixture(tmp_path, verifier)
    alternate = bytearray(
        _gzip_payload(raw_tar, epoch, compresslevel=1))
    alternate[8] = 2  # Forge the level-9 XFL byte while retaining level-1 DEFLATE.
    sdist.write_bytes(alternate)

    with pytest.raises(SystemExit, match="complete gzip envelope is not canonical"):
        verifier._validated_sdist_payload(sdist, ROOT, expected_epoch=epoch)


def test_portable_semantic_sdist_accepts_alternate_deflate_encoding(tmp_path):
    verifier = _load_release_script("verify_distributions")
    sdist, _, epoch, raw_tar = _canonical_sdist_fixture(tmp_path, verifier)
    alternate = bytearray(_gzip_payload(raw_tar, epoch, compresslevel=1))
    alternate[8] = 2
    assert bytes(alternate) != verifier._canonical_gzip_bytes(raw_tar, epoch)
    sdist.write_bytes(alternate)

    verifier._validated_sdist_payload(
        sdist, ROOT, expected_epoch=epoch,
        verify_recompression_bytes=False)


def test_portable_semantic_verification_works_from_sdist_without_git(
        tmp_path, monkeypatch):
    checkout_verifier = _load_release_script("verify_distributions")
    sdist, wheel, epoch, raw_tar = _canonical_sdist_fixture(
        tmp_path, checkout_verifier)
    extracted = checkout_verifier._extract_validated_sdist(
        sdist, tmp_path / "extracted", ROOT, expected_epoch=epoch)
    assert not (extracted / ".git").exists()

    verifier = _load_release_script("verify_distributions", extracted)

    def reject_git_lookup(*args, **kwargs):
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(verifier, "_commit_epoch", reject_git_lookup)
    alternate = bytearray(_gzip_payload(raw_tar, epoch, compresslevel=1))
    alternate[8] = 2
    sdist.write_bytes(alternate)
    with zipfile.ZipFile(wheel) as wheel_archive:
        verifier._validated_sdist_payload(
            sdist, extracted, expected_epoch=epoch, wheel=wheel_archive,
            verify_recompression_bytes=False)


def test_distribution_verifier_cli_routes_strict_and_portable_modes(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w"):
        pass
    sdist = tmp_path / "fixture.tar.gz"
    sdist.write_bytes(b"fixture")
    epoch = 1700000000
    calls = []
    behavior_calls = []

    monkeypatch.setattr(
        verifier, "_release_assets", lambda dist: (wheel, sdist))
    monkeypatch.setattr(verifier, "_verify_checksums", lambda *args: None)

    def wheel_envelope(path, source_root, **kwargs):
        calls.append(("wheel", path, source_root, kwargs))

    def sdist_payload(path, source_root, **kwargs):
        calls.append(("sdist", path, source_root, kwargs))
        return "fixture", set(), {}

    monkeypatch.setattr(verifier, "_verify_wheel_envelope", wheel_envelope)
    monkeypatch.setattr(verifier, "_validated_sdist_payload", sdist_payload)
    monkeypatch.setattr(verifier, "_verify_wheel_runtime_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_evidence_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_normative_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_generated_contract", lambda *args: None)
    monkeypatch.setattr(
        verifier, "_verify_behavior",
        lambda *args, **kwargs: behavior_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(verifier, "_commit_epoch", lambda source_root: epoch)
    monkeypatch.setattr(
        verifier, "_require_exact_git_source", lambda source_root: None)

    assert verifier.main([str(tmp_path)]) == 0
    assert [call[3]["verify_recompression_bytes"] for call in calls] == [True, True]
    assert [call[3]["expected_epoch"] for call in calls] == [epoch, epoch]
    assert behavior_calls == [((tmp_path,), {})]

    calls.clear()
    behavior_calls.clear()

    def reject_git_lookup(*args, **kwargs):
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(verifier, "_commit_epoch", reject_git_lookup)
    assert verifier.main([
        "--portable-semantic", "--source-epoch", str(epoch), str(tmp_path),
    ]) == 0
    assert [call[3]["verify_recompression_bytes"] for call in calls] == [False, False]
    assert [call[3]["expected_epoch"] for call in calls] == [epoch, epoch]
    assert behavior_calls == [((tmp_path,), {})]


def test_distribution_structural_verification_cannot_run_artifact_behavior(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "causal_continuity_engine-0.1.5-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w"):
        pass
    sdist = tmp_path / "causal_continuity_engine-0.1.5.tar.gz"
    sdist.write_bytes(b"pre-behavior-sdist")
    artifacts = [wheel, sdist]

    def write_manifest():
        (tmp_path / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in sorted(artifacts, key=lambda item: item.name)
            ),
            encoding="ascii",
            newline="\n",
        )

    write_manifest()
    before = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (*artifacts, tmp_path / "SHA256SUMS")
    }
    monkeypatch.setattr(
        verifier, "_release_assets", lambda dist: (wheel, sdist))
    monkeypatch.setattr(
        verifier, "_require_exact_git_source", lambda source_root: None)
    monkeypatch.setattr(verifier, "_commit_epoch", lambda source_root: 1700000000)
    monkeypatch.setattr(verifier, "_verify_wheel_envelope", lambda *args, **kwargs: None)
    monkeypatch.setattr(verifier, "_archive_names_are_safe", lambda *args: None)
    monkeypatch.setattr(verifier, "_validated_sdist_payload", lambda *args, **kwargs: None)
    monkeypatch.setattr(verifier, "_verify_wheel_runtime_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_evidence_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_normative_payload", lambda *args: None)
    monkeypatch.setattr(verifier, "_verify_wheel_generated_contract", lambda *args: None)

    def artifact_behavior(_wheel):
        wheel.write_bytes(b"post-behavior-wheel")
        sdist.write_bytes(b"post-behavior-sdist")
        write_manifest()

    monkeypatch.setattr(verifier, "_verify_installed_wheel", artifact_behavior)

    assert verifier.main(["--structural-only", str(tmp_path)]) == 0
    after = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (*artifacts, tmp_path / "SHA256SUMS")
    }
    assert after == before


def test_distribution_verifier_separates_structural_and_behavior_modes(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w"):
        pass
    sdist = tmp_path / "fixture.tar.gz"
    sdist.write_bytes(b"fixture")
    calls = []

    monkeypatch.setattr(
        verifier, "_release_assets",
        lambda dist: calls.append("assets") or (wheel, sdist),
    )
    monkeypatch.setattr(
        verifier, "_verify_checksums",
        lambda *args: calls.append("checksums"),
    )
    monkeypatch.setattr(
        verifier, "_require_exact_git_source",
        lambda *args: calls.append("git"),
    )
    monkeypatch.setattr(
        verifier, "_commit_epoch", lambda *args: calls.append("epoch") or 1700000000)
    monkeypatch.setattr(
        verifier, "_verify_wheel_envelope",
        lambda *args, **kwargs: calls.append("wheel"),
    )
    monkeypatch.setattr(
        verifier, "_archive_names_are_safe",
        lambda *args: calls.append("archive"),
    )
    monkeypatch.setattr(
        verifier, "_validated_sdist_payload",
        lambda *args, **kwargs: calls.append("sdist"),
    )
    for name, label in (
        ("_verify_wheel_runtime_payload", "runtime"),
        ("_verify_wheel_evidence_payload", "evidence"),
        ("_verify_wheel_normative_payload", "normative"),
        ("_verify_wheel_generated_contract", "generated"),
    ):
        monkeypatch.setattr(
            verifier, name, lambda *args, _label=label: calls.append(_label))
    monkeypatch.setattr(
        verifier, "_verify_behavior",
        lambda *args, **kwargs: calls.append("behavior"),
    )

    assert verifier.main(["--structural-only", str(tmp_path)]) == 0
    assert calls == [
        "epoch", "git", "assets", "checksums", "wheel", "archive", "sdist",
        "runtime", "evidence", "normative", "generated",
    ]

    calls.clear()
    assert verifier.main(["--behavior-only", str(tmp_path)]) == 0
    assert calls == ["behavior"]

    calls.clear()
    assert verifier.main([str(tmp_path)]) == 0
    assert calls == [
        "epoch", "git", "assets", "checksums", "wheel", "archive", "sdist",
        "runtime", "evidence", "normative", "generated", "behavior",
    ]


def _behavior_release_set(root):
    wheel = root / f"causal_continuity_engine-{runtime_package.__version__}-py3-none-any.whl"
    sdist = root / SDIST_NAME
    wheel.write_bytes(b"captured-wheel-a")
    sdist.write_bytes(b"captured-sdist-a")
    manifest = root / "SHA256SUMS"
    artifacts = (wheel, sdist)
    manifest.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(artifacts, key=lambda item: item.name)
        ),
        encoding="ascii",
        newline="\n",
    )
    return wheel, sdist, manifest


def test_behavior_executes_a_private_copy_of_the_manifest_wheel(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    wheel, _, _ = _behavior_release_set(tmp_path)
    original_wheel = wheel.read_bytes()
    observed = []

    def verify_private_wheel(captured):
        observed.append((captured, captured.read_bytes(), captured.stat().st_mode & 0o777))
        wheel.write_bytes(b"public-wheel-mutated-after-capture")

    monkeypatch.setattr(verifier, "_verify_installed_wheel", verify_private_wheel)
    assert verifier.main([
        "--behavior-only",
        str(tmp_path),
    ]) == 0

    assert len(observed) == 1
    captured, body, mode = observed[0]
    assert captured != wheel
    assert body == original_wheel
    assert mode & 0o222 == 0
    assert wheel.read_bytes() == b"public-wheel-mutated-after-capture"


def test_behavior_rejects_a_manifest_substitution_before_execution(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    wheel, _, _ = _behavior_release_set(tmp_path)
    wheel.write_bytes(b"substituted-wheel")
    executed = []
    monkeypatch.setattr(
        verifier, "_verify_installed_wheel", lambda *args: executed.append(args))

    with pytest.raises(
            SystemExit, match="does not exactly describe the captured release set"):
        verifier.main([
            "--behavior-only",
            str(tmp_path),
        ])
    assert executed == []
    assert wheel.read_bytes() == b"substituted-wheel"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_behavior_capture_rejects_a_fifo_without_opening_it(tmp_path):
    verifier = _load_release_script("verify_distributions")
    fifo = tmp_path / "candidate.whl"
    os.mkfifo(fifo)

    with pytest.raises(SystemExit, match="physical regular file"):
        verifier._stable_regular_file_bytes(
            fifo, verifier.MAX_WHEEL_ARCHIVE_BYTES, label="behavior wheel")


def test_behavior_capture_rejects_symlinks(tmp_path):
    verifier = _load_release_script("verify_distributions")
    original = tmp_path / "original.whl"
    original.write_bytes(b"wheel")
    symlink = tmp_path / "symlink.whl"
    try:
        symlink.symlink_to(original)
    except OSError as exc:
        pytest.skip(f"symlink fixtures are unavailable: {exc}")

    with pytest.raises(SystemExit, match="physical regular file"):
        verifier._stable_regular_file_bytes(
            symlink, verifier.MAX_WHEEL_ARCHIVE_BYTES, label="behavior wheel")


def test_behavior_capture_rejects_hardlinks(tmp_path):
    verifier = _load_release_script("verify_distributions")
    original = tmp_path / "original.whl"
    original.write_bytes(b"wheel")
    hardlink = tmp_path / "hardlink.whl"
    try:
        os.link(original, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink fixtures are unavailable: {exc}")

    with pytest.raises(SystemExit, match="single-link regular file"):
        verifier._stable_regular_file_bytes(
            hardlink, verifier.MAX_WHEEL_ARCHIVE_BYTES, label="behavior wheel")


def test_behavior_capture_rejects_oversize_files(tmp_path):
    verifier = _load_release_script("verify_distributions")

    oversize = tmp_path / "oversize.whl"
    with oversize.open("wb") as stream:
        stream.seek(verifier.MAX_WHEEL_ARCHIVE_BYTES)
        stream.write(b"x")
    with pytest.raises(SystemExit, match="exceeds the size limit"):
        verifier._stable_regular_file_bytes(
            oversize, verifier.MAX_WHEEL_ARCHIVE_BYTES, label="behavior wheel")


@pytest.mark.parametrize(("target_name", "maximum", "message"), [
    ("candidate.whl", "MAX_WHEEL_ARCHIVE_BYTES", "checksum wheel exceeds"),
    ("candidate.tar.gz", "MAX_SDIST_ARCHIVE_BYTES", "checksum sdist exceeds"),
    ("SHA256SUMS", "MAX_CHECKSUM_MANIFEST_BYTES", "checksum manifest exceeds"),
])
def test_distribution_checksum_verification_bounds_inputs_before_read(
        tmp_path, target_name, maximum, message):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "candidate.whl"
    sdist = tmp_path / "candidate.tar.gz"
    manifest = tmp_path / "SHA256SUMS"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest.write_bytes(b"manifest")
    target = tmp_path / target_name
    with target.open("wb") as stream:
        stream.seek(getattr(verifier, maximum))
        stream.write(b"x")

    with pytest.raises(SystemExit, match=message):
        verifier._verify_checksums(tmp_path, [wheel, sdist])


@pytest.mark.parametrize("args", [
    ["--portable-semantic"],
    ["--source-epoch", "1700000000"],
])
def test_distribution_verifier_cli_requires_explicit_paired_portable_flags(args):
    verifier = _load_release_script("verify_distributions")

    with pytest.raises(SystemExit) as caught:
        verifier.main(args)
    assert caught.value.code == 2


def test_installed_audit_modules_are_available_only_to_scoped_audit_process(
        tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    environment_root = tmp_path / "clean-venv"
    verifier.venv.EnvBuilder(with_pip=False).create(environment_root)
    python = verifier._venv_python(environment_root)
    ambient = tmp_path / "ambient"
    (ambient / "tests").mkdir(parents=True)
    (ambient / "tests" / "__init__.py").write_text(
        "AMBIENT = True\n", encoding="utf-8")
    (ambient / "ambient_release_poison.py").write_text(
        "BOUND = True\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(ambient))
    monkeypatch.setenv("CCE_RELEASE_SECRET_CANARY", "must-not-cross-boundary")
    monkeypatch.setenv("HTTPS_PROXY", "http://must-not-cross-boundary.invalid")
    audit_root = (
        tmp_path / "share" / "causal-continuity-engine" / "audit")
    audit_package = audit_root / "verifiers"
    audit_package.mkdir(parents=True)
    (audit_package / "__init__.py").write_text("", encoding="utf-8")
    (audit_package / "verify_proof.py").write_text(
        "SENTINEL = 'owned-audit-module'\n", encoding="utf-8")
    audit_tests = audit_root / "tests"
    audit_tests.mkdir()
    (audit_tests / "__init__.py").write_text("", encoding="utf-8")
    (audit_tests / "schema_validation.py").write_text(
        "SENTINEL = 'owned-schema-helper'\n", encoding="utf-8")
    distribution_environment_test = (
        audit_tests / "test_distribution_environment.py")
    distribution_environment_test.write_bytes(
        (ROOT / "tests" / "test_distribution_environment.py").read_bytes())
    outside = tmp_path / "outside"
    outside.mkdir()
    clean_env = verifier._clean_subprocess_environment(
        tmp_path / "process-environment", python.parent)
    assert "PYTHONPATH" not in clean_env
    assert "CCE_RELEASE_SECRET_CANARY" not in clean_env
    assert "HTTPS_PROXY" not in clean_env
    assert clean_env["PIP_NO_INDEX"] == "1"
    process_root = (tmp_path / "process-environment").resolve()
    for name in (
            "HOME", "USERPROFILE", "TMP", "TEMP", "XDG_CACHE_HOME",
            "PIP_CACHE_DIR"):
        assert Path(clean_env[name]).resolve().is_relative_to(process_root)

    # Exercise the copier against a synthetic hash lock for the exact host
    # distributions used by this test run. The release path separately reads
    # the repository lock and rejects any host-version difference.
    lock_root = tmp_path / "lock-root"
    lock_root.mkdir()
    locked_lines = []
    for name in sorted(verifier._active_audit_tool_distributions()):
        version = verifier.importlib.metadata.distribution(name).version
        locked_lines.append(
            f"{name}=={version} \\\n"
            f"    --hash=sha256:{'0' * 64}\n")
    (lock_root / "requirements-dev.lock").write_text(
        "".join(locked_lines), encoding="utf-8", newline="\n")
    verifier._run_checked(
        [
            str(python), "-I", "-c",
            "import os, pathlib, sys; "
            "forbidden = ('CCE_RELEASE_SECRET_CANARY', 'HTTPS_PROXY', 'PYTHONPATH'); "
            "assert not any(name in os.environ for name in forbidden); "
            "assert pathlib.Path(os.environ['HOME']).resolve().is_relative_to("
            "pathlib.Path(sys.argv[1]).resolve())",
            str(process_root),
        ],
        cwd=outside, environment=clean_env,
        label="clean subprocess environment canary probe", timeout_seconds=30,
    )
    host_bases = {
        Path(verifier.importlib.metadata.distribution(name).locate_file("")).resolve()
        for name in verifier._active_audit_tool_distributions()
    }
    original_get_path = verifier.sysconfig.get_path
    monkeypatch.setattr(
        verifier.sysconfig, "get_path",
        lambda name: str(next(iter(host_bases)))
        if name in {"purelib", "platlib"} and len(host_bases) == 1
        else original_get_path(name))
    if len(host_bases) != 1:
        pytest.skip("exact-copy fixture requires one controlled host package root")
    verifier._install_locked_audit_tools(python, clean_env, lock_root)
    verifier._run_checked(
        [
            str(python), "-I", "-c",
            "from importlib.util import find_spec; "
            "names = ('tests', 'verifiers', 'ambient_release_poison', 'build', 'ruff'); "
            "found = {name: find_spec(name) for name in names "
            "if find_spec(name) is not None}; raise SystemExit(bool(found))",
        ],
        cwd=outside, environment=clean_env,
        label="clean audit-namespace isolation probe", timeout_seconds=30,
    )
    assert "PYTHONPATH" not in clean_env
    verifier._run_checked(
        [
            str(python), "-P", "-c", verifier._AUDIT_IMPORT_PROBE,
            str(audit_root),
        ],
        cwd=outside, environment=clean_env,
        label="scoped audit-module import probe", timeout_seconds=30,
    )
    verifier._run_checked(
        verifier._wheel_behavior_test_command(
            python, audit_root, [str(distribution_environment_test)]),
        cwd=outside, environment=clean_env,
        label="clean installed-wheel environment probe", timeout_seconds=30,
    )


def test_installed_cli_smoke_prepares_existing_project_directory(tmp_path):
    verifier = _load_release_script("verify_distributions")
    expected = tmp_path / "cli-project"
    assert not expected.exists()

    prepared = verifier._prepare_cli_smoke_directory(tmp_path)

    assert prepared == expected
    assert prepared.is_dir()


def test_release_subprocess_runner_returns_bounded_clean_success(tmp_path):
    verifier = _load_release_script("verify_distributions")
    environment = verifier._clean_subprocess_environment(
        tmp_path / "process-environment", Path(verifier.sys.executable).parent)

    result = verifier._run_checked(
        [verifier.sys.executable, "-I", "-c", "print('bounded-success')"],
        cwd=tmp_path, environment=environment, label="bounded success",
        timeout_seconds=10)

    expected = "bounded-success\r\n" \
        if verifier.os.name == "nt" else "bounded-success\n"
    assert result.stdout == expected


def test_release_subprocess_runner_terminates_hang(tmp_path):
    verifier = _load_release_script("verify_distributions")
    environment = verifier._clean_subprocess_environment(
        tmp_path / "process-environment", Path(verifier.sys.executable).parent)
    started = verifier.time.monotonic()

    with pytest.raises(SystemExit, match="timed out after 1s"):
        verifier._run_checked(
            [verifier.sys.executable, "-I", "-c", "import time; time.sleep(60)"],
            cwd=tmp_path, environment=environment, label="planted hang",
            timeout_seconds=1)

    assert verifier.time.monotonic() - started < 10


@pytest.mark.parametrize("descriptor", [1, 2], ids=("stdout", "stderr"))
def test_release_subprocess_runner_terminates_output_flood(
        tmp_path, descriptor):
    verifier = _load_release_script("verify_distributions")
    environment = verifier._clean_subprocess_environment(
        tmp_path / f"process-environment-{descriptor}",
        Path(verifier.sys.executable).parent)
    command = (
        "import os; "
        f"os.write({descriptor}, b'x' * "
        f"({verifier.MAX_SUBPROCESS_OUTPUT_BYTES + 65536}))"
    )

    with pytest.raises(SystemExit, match="exceeded the output limit") as caught:
        verifier._run_checked(
            [verifier.sys.executable, "-I", "-c", command],
            cwd=tmp_path, environment=environment, label="planted output flood",
            timeout_seconds=10)

    assert "output truncated at release-verifier cap" in str(caught.value)
    assert len(str(caught.value)) < verifier.MAX_SUBPROCESS_OUTPUT_BYTES + 2048


def test_release_subprocess_timeout_kills_descendant_tree(tmp_path):
    verifier = _load_release_script("verify_distributions")
    marker = tmp_path / "descendant-survived"
    child = tmp_path / "child.py"
    child.write_text(
        "import pathlib, sys, time\n"
        "time.sleep(2)\n"
        "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')\n",
        encoding="utf-8", newline="\n")
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
        "time.sleep(60)\n",
        encoding="utf-8", newline="\n")
    environment = verifier._clean_subprocess_environment(
        tmp_path / "process-environment", Path(verifier.sys.executable).parent)

    with pytest.raises(SystemExit, match="timed out after 1s"):
        verifier._run_checked(
            [verifier.sys.executable, "-I", str(parent), str(child), str(marker)],
            cwd=tmp_path, environment=environment, label="planted descendant hang",
            timeout_seconds=1)
    verifier.time.sleep(2.5)

    assert not marker.exists()


def _canonical_wheel_fixture(tmp_path, verifier):
    epoch = verifier._commit_epoch(ROOT)
    payload = {"a.py": b"A = 1\n", "b.py": b"B = 2\n"}
    wheel = tmp_path / "causal_continuity_engine-0.1.0-py3-none-any.whl"
    wheel.write_bytes(verifier._canonical_wheel_bytes(payload, epoch))
    return wheel, epoch, payload


def _zip_with_local_only_extra(raw):
    extra = b"\xfe\xca\x00\x00"
    mutated = bytearray(raw)
    local = mutated.find(b"PK\x03\x04")
    name_length = int.from_bytes(mutated[local + 26:local + 28], "little")
    insertion = local + 30 + name_length
    mutated[local + 28:local + 30] = len(extra).to_bytes(2, "little")
    mutated[insertion:insertion] = extra
    eocd = mutated.rfind(b"PK\x05\x06")
    central_offset = int.from_bytes(mutated[eocd + 16:eocd + 20], "little")
    mutated[eocd + 16:eocd + 20] = (
        central_offset + len(extra)).to_bytes(4, "little")
    return bytes(mutated)


def _zip_with_central_only_extra(raw):
    extra = b"\xfe\xca\x00\x00"
    mutated = bytearray(raw)
    eocd = mutated.rfind(b"PK\x05\x06")
    central = int.from_bytes(mutated[eocd + 16:eocd + 20], "little")
    name_length = int.from_bytes(mutated[central + 28:central + 30], "little")
    insertion = central + 46 + name_length
    mutated[central + 30:central + 32] = len(extra).to_bytes(2, "little")
    mutated[insertion:insertion] = extra
    eocd = mutated.rfind(b"PK\x05\x06")
    central_size = int.from_bytes(mutated[eocd + 12:eocd + 16], "little")
    mutated[eocd + 12:eocd + 16] = (
        central_size + len(extra)).to_bytes(4, "little")
    return bytes(mutated)


def test_distribution_verifier_accepts_canonical_complete_zip(tmp_path):
    verifier = _load_release_script("verify_distributions")
    wheel, epoch, _ = _canonical_wheel_fixture(tmp_path, verifier)

    verifier._verify_wheel_envelope(wheel, ROOT, expected_epoch=epoch)


def test_portable_semantic_wheel_accepts_alternate_deflate_encoding(tmp_path):
    verifier = _load_release_script("verify_distributions")
    epoch = verifier._commit_epoch(ROOT)
    payload = {
        "audit.txt": b"causal-continuity-engine semantic payload\n" * 16384,
    }
    rendered = io.BytesIO()
    timestamp = verifier.time.gmtime(epoch)[:6]
    with zipfile.ZipFile(rendered, "w") as archive:
        for name, body in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info, body, compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=1)
    wheel = tmp_path / "causal_continuity_engine-0.1.0-py3-none-any.whl"
    wheel.write_bytes(rendered.getvalue())
    assert wheel.read_bytes() != verifier._canonical_wheel_bytes(payload, epoch)

    verifier._verify_wheel_envelope(
        wheel, ROOT, expected_epoch=epoch,
        verify_recompression_bytes=False)
    with pytest.raises(SystemExit, match="complete ZIP envelope is not canonical"):
        verifier._verify_wheel_envelope(wheel, ROOT, expected_epoch=epoch)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: b"prefix" + raw,
        lambda raw: raw + b"tail",
        _zip_with_local_only_extra,
        _zip_with_central_only_extra,
    ],
    ids=("prefix", "tail", "local-extra", "central-extra"),
)
@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
def test_distribution_verifier_rejects_zip_boundary_and_extra_fields(
        tmp_path, mutation, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    wheel, epoch, _ = _canonical_wheel_fixture(tmp_path, verifier)
    wheel.write_bytes(mutation(wheel.read_bytes()))

    with pytest.raises(SystemExit, match="ZIP (?:archive|envelope)"):
        verifier._verify_wheel_envelope(
            wheel, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
def test_distribution_verifier_rejects_zip_comment(
        tmp_path, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    wheel, epoch, _ = _canonical_wheel_fixture(tmp_path, verifier)
    mutated = bytearray(wheel.read_bytes())
    eocd = mutated.rfind(b"PK\x05\x06")
    mutated[eocd + 20:eocd + 22] = (1).to_bytes(2, "little")
    mutated.extend(b"x")
    wheel.write_bytes(mutated)

    with pytest.raises(SystemExit, match="ZIP envelope is not canonical"):
        verifier._verify_wheel_envelope(
            wheel, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


@pytest.mark.parametrize(
    "variation", ["order", "timestamp", "mode", "compression", "flags"])
@pytest.mark.parametrize("verify_recompression_bytes", [True, False])
def test_distribution_verifier_rejects_noncanonical_zip_metadata(
        tmp_path, variation, verify_recompression_bytes):
    verifier = _load_release_script("verify_distributions")
    wheel, epoch, payload = _canonical_wheel_fixture(tmp_path, verifier)
    names = sorted(payload, reverse=variation == "order")
    rendered = io.BytesIO()
    timestamp = verifier.time.gmtime(epoch)[:6]
    with zipfile.ZipFile(rendered, "w") as archive:
        for name in names:
            date_time = (2020, 1, 2, 3, 4, 6) \
                if variation == "timestamp" else timestamp
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.create_system = 3
            info.external_attr = (
                (0o100600 if variation == "mode" else 0o100644) << 16)
            compression = zipfile.ZIP_STORED \
                if variation == "compression" else zipfile.ZIP_DEFLATED
            archive.writestr(
                info, payload[name], compress_type=compression, compresslevel=9)
    raw = bytearray(rendered.getvalue())
    if variation == "flags":
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        for offset in (local + 6, central + 8):
            flags = int.from_bytes(raw[offset:offset + 2], "little") | 0x800
            raw[offset:offset + 2] = flags.to_bytes(2, "little")
    wheel.write_bytes(raw)

    with pytest.raises(SystemExit, match="ZIP envelope is not canonical"):
        verifier._verify_wheel_envelope(
            wheel, ROOT, expected_epoch=epoch,
            verify_recompression_bytes=verify_recompression_bytes)


def _write_portable_source_ledger(source_root):
    verifier = _load_release_script("verify_distributions")
    required = (
        verifier.SDIST_ROOT_FILES
        | verifier.GITHUB_ROOT_FILES
        | verifier.GITHOOK_FILES
    )
    for relative in sorted(required):
        path = source_root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"fixture: {relative}\n", encoding="utf-8", newline="\n")
    examples = {
        "benchmarks": "benchmarks/owned.py",
        "causal_continuity_engine": "causal_continuity_engine/owned.py",
        "docs": "docs/owned.md",
        "examples": "examples/owned.py",
        "schemas": "schemas/owned.json",
        "tests": "tests/owned.py",
        "vectors": "vectors/owned.py",
        "verifiers": "verifiers/owned.py",
        ".github/ISSUE_TEMPLATE": ".github/ISSUE_TEMPLATE/owned.yml",
        ".github/scripts": ".github/scripts/owned.py",
        ".github/workflows": ".github/workflows/owned.yml",
    }
    for tree, relative in examples.items():
        if any(
                path.is_file()
                and path.relative_to(source_root).as_posix().startswith(tree + "/")
                and verifier._source_path_is_allowed(
                    path.relative_to(source_root).as_posix())
                for path in source_root.rglob("*")):
            continue
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8", newline="\n")
    source_names = sorted(
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*")
        if path.is_file()
        and verifier._source_path_is_allowed(path.relative_to(source_root).as_posix())
    )
    generated = sorted(
        name for name in verifier.SDIST_GENERATED_FILES
        if name.startswith(verifier.EGG_INFO + "/"))
    ledger = source_root / verifier.EGG_INFO / "SOURCES.txt"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(
        "".join(f"{name}\n" for name in sorted(source_names + generated)),
        encoding="utf-8", newline="\n")


def _runtime_wheel_fixture(tmp_path, wheel_payload):
    source_root = tmp_path / "source"
    package = source_root / "causal_continuity_engine"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b'__version__ = "0.1.0"\n')
    (package / "api.py").write_bytes(b"VALUE = 'reviewed'\n")
    (package / "py.typed").write_bytes(b"")
    _write_portable_source_ledger(source_root)
    wheel = tmp_path / "causal_continuity_engine.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, body in wheel_payload.items():
            archive.writestr(name, body)
    return source_root, wheel


def test_distribution_verifier_rejects_altered_runtime_module(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _runtime_wheel_fixture(tmp_path, {
        "causal_continuity_engine/__init__.py": b'__version__ = "0.1.0"\n',
        "causal_continuity_engine/api.py": b"VALUE = 'substituted'\n",
        "causal_continuity_engine/py.typed": b"",
    })

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match=r"bytes differ.*causal_continuity_engine/api\.py"):
            verifier._verify_wheel_runtime_payload(archive, source_root)


def test_distribution_verifier_rejects_omitted_runtime_module(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _runtime_wheel_fixture(tmp_path, {
        "causal_continuity_engine/__init__.py": b'__version__ = "0.1.0"\n',
        "causal_continuity_engine/py.typed": b"",
    })

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match=r"missing: causal_continuity_engine/api\.py"):
            verifier._verify_wheel_runtime_payload(archive, source_root)


def _contract_wheel_fixture(
        tmp_path, *, extra=None, metadata_extra="", entry_points=None,
        metadata_version="0.1.0", citation_version="0.1.0",
        corrupt_record=False):
    source_root = tmp_path / "source"
    package = source_root / "causal_continuity_engine"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b'__version__ = "0.1.0"\n')
    (package / "py.typed").write_bytes(b"")
    (source_root / "schemas").mkdir()
    (source_root / "SPEC.md").write_bytes(b"spec\n")
    (source_root / "LICENSE.txt").write_bytes(b"license\n")
    (source_root / "NOTICE").write_bytes(b"notice\n")
    audit_sources = {
        "benchmarks/continuitybench/run.py": b"BENCHMARK = True\n",
        "tests/test_cli.py": b"def test_cli():\n    pass\n",
        "vectors/generate.py": b"GENERATOR = True\n",
        "vectors/index.json": b"{}\n",
        "verifiers/verify_proof.py": b"VERIFIER = True\n",
    }
    for relative, body in audit_sources.items():
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (source_root / "CITATION.cff").write_text(
        f"cff-version: 1.2.0\nversion: {citation_version}\n",
        encoding="utf-8",
    )
    (source_root / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "causal-continuity-engine"
dynamic = ["version"]
requires-python = ">=3.11"

[project.optional-dependencies]
dev = ["pytest==9.0.2"]

[tool.setuptools.dynamic]
version = { attr = "causal_continuity_engine.__version__" }
""",
        encoding="utf-8",
    )
    _write_portable_source_ledger(source_root)
    dist_root = "causal_continuity_engine-0.1.0.dist-info"
    data_root = "causal_continuity_engine-0.1.0.data"
    payload = {
        "causal_continuity_engine/__init__.py": b'__version__ = "0.1.0"\n',
        "causal_continuity_engine/py.typed": b"",
        f"{data_root}/data/share/causal-continuity-engine/audit/SPEC.md": b"spec\n",
        f"{data_root}/data/share/causal-continuity-engine/audit/"
        "schemas/owned.json": b"fixture\n",
        f"{dist_root}/licenses/LICENSE.txt": b"license\n",
        f"{dist_root}/licenses/NOTICE": b"notice\n",
        f"{dist_root}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: causal-continuity-engine\n"
            f"Version: {metadata_version}\n"
            "Requires-Python: >=3.11\n"
            "Provides-Extra: dev\n"
            'Requires-Dist: pytest==9.0.2; extra == "dev"\n'
            f"{metadata_extra}\n"
        ).encode("utf-8"),
        f"{dist_root}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: setuptools (80.9.0)\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
        f"{dist_root}/entry_points.txt": entry_points or (
            b"[console_scripts]\ncce-engine = causal_continuity_engine.cli:main\n"),
        f"{dist_root}/top_level.txt": b"causal_continuity_engine\n",
    }
    payload.update({
        f"{data_root}/data/share/causal-continuity-engine/audit/{relative}": body
        for relative, body in audit_sources.items()
    })
    payload.update(extra or {})
    record_name = f"{dist_root}/RECORD"
    record = []
    for name, body in sorted(payload.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=")
        encoded = digest.decode("ascii")
        if corrupt_record and name == "causal_continuity_engine/__init__.py":
            encoded = "A" * 43
        record.append(f"{name},sha256={encoded},{len(body)}\n")
    record.append(f"{record_name},,\n")
    payload[record_name] = "".join(record).encode("utf-8")

    wheel = tmp_path / "causal_continuity_engine.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, body in payload.items():
            archive.writestr(name, body)
    return source_root, wheel


def test_release_version_is_exclusively_runtime_derived():
    verifier = _load_release_script("verify_distributions")
    project, version = verifier._project_contract(ROOT)

    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "causal_continuity_engine.__version__",
    }
    assert version == runtime_package.__version__
    assert verifier._citation_version(ROOT) == runtime_package.__version__


def test_distribution_verifier_accepts_matching_runtime_and_metadata_version(
        tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(tmp_path)

    with zipfile.ZipFile(wheel) as archive:
        verifier._verify_wheel_generated_contract(archive, source_root)


def test_wheel_has_one_import_namespace_and_distribution_owned_audit_data(
        tmp_path):
    verifier = _load_release_script("verify_distributions")
    project, _ = verifier._project_contract(ROOT)
    package_find = project["tool"]["setuptools"]["packages"]["find"]
    data_files = project["tool"]["setuptools"]["data-files"]
    assert package_find == {
        "include": ["causal_continuity_engine*"],
        "namespaces": False,
    }
    assert set(data_files) == {
        "share/causal-continuity-engine/audit",
        "share/causal-continuity-engine/audit/schemas",
        "share/causal-continuity-engine/audit/benchmarks",
        "share/causal-continuity-engine/audit/benchmarks/continuitybench",
        "share/causal-continuity-engine/audit/tests",
        "share/causal-continuity-engine/audit/vectors",
        "share/causal-continuity-engine/audit/verifiers",
    }

    source_root, wheel = _contract_wheel_fixture(tmp_path)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        dist_root = next(name.split("/", 1)[0] for name in names
                         if name.endswith(".dist-info/top_level.txt"))
        assert archive.read(f"{dist_root}/top_level.txt") == (
            b"causal_continuity_engine\n")
        for generic in verifier.WHEEL_EVIDENCE_TREES:
            assert not any(name.startswith(generic + "/") for name in names)
        verifier._verify_wheel_evidence_payload(archive, source_root)
        verifier._verify_wheel_generated_contract(archive, source_root)


@pytest.mark.parametrize("generic", ["benchmarks", "tests", "vectors", "verifiers"])
def test_distribution_verifier_rejects_generic_wheel_audit_namespaces(
        tmp_path, generic):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, extra={f"{generic}/unexpected.py": b"VALUE = True\n"})

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match="generic top-level audit namespaces"):
            verifier._verify_wheel_evidence_payload(archive, source_root)


def test_distribution_verifier_rejects_metadata_runtime_version_drift(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, metadata_version="0.1.1")

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(
                SystemExit, match="METADATA version differs from runtime __version__"):
            verifier._verify_wheel_generated_contract(archive, source_root)


def test_distribution_verifier_rejects_citation_runtime_version_drift(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, citation_version="0.1.1")

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(
                SystemExit, match="CITATION.cff version differs from runtime __version__"):
            verifier._verify_wheel_generated_contract(archive, source_root)


@pytest.mark.parametrize("extra_name", [
    "evil.pth",
    "sitecustomize.py",
    "causal_continuity_engine-0.1.0.data/purelib/evil.pth",
    "cce/__init__.py",
    "build/lib/cce/api.py",
])
def test_distribution_verifier_rejects_unmodeled_startup_payload(
        tmp_path, extra_name):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, extra={extra_name: b"raise SystemExit('executed')\n"})

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match="exhaustive member manifest differs"):
            verifier._verify_wheel_generated_contract(archive, source_root)


@pytest.mark.parametrize("names, diagnostic", [
    (["C:/payload.pth"], "unsafe archive path"),
    (["NUL.txt"], "unsafe archive path"),
    (
        ["causal_continuity_engine/api.py", "CAUSAL_CONTINUITY_ENGINE/API.PY"],
        "collide cross-platform",
    ),
    (
        ["package/Dir/a.py", "package/dir/b.py"],
        "directory prefixes collide cross-platform",
    ),
    (
        ["package/Dir", "package/dir/child.py"],
        "file/directory paths collide cross-platform",
    ),
])
def test_distribution_verifier_rejects_nonportable_wheel_paths(
        tmp_path, names, diagnostic):
    verifier = _load_release_script("verify_distributions")
    wheel = tmp_path / "causal_continuity_engine.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in names:
            archive.writestr(name, b"payload")

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match=diagnostic):
            verifier._archive_names_are_safe(archive)


def test_distribution_verifier_rejects_runtime_dependency_metadata(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, metadata_extra="Requires-Dist: surprise==1.0")

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match="runtime or non-exact dependency"):
            verifier._verify_wheel_generated_contract(archive, source_root)


def test_distribution_verifier_rejects_substituted_console_entrypoint(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path,
        entry_points=b"[console_scripts]\ncce-engine = sitecustomize:main\n")

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match="console entry points differ"):
            verifier._verify_wheel_generated_contract(archive, source_root)


def test_distribution_verifier_rejects_false_record_digest(tmp_path):
    verifier = _load_release_script("verify_distributions")
    source_root, wheel = _contract_wheel_fixture(
        tmp_path, corrupt_record=True)

    with zipfile.ZipFile(wheel) as archive:
        with pytest.raises(SystemExit, match="RECORD digest or size differs"):
            verifier._verify_wheel_generated_contract(archive, source_root)


def test_release_rejects_unsigned_annotated_tag(monkeypatch):
    checker = _load_release_script("check_release_tag")
    version = runtime_package.__version__
    tag = f"v{version}"
    monkeypatch.setattr(
        checker, "_verify_release_metadata", lambda name: version)

    def fake_git(*args):
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        raise AssertionError(args)

    monkeypatch.setattr(checker, "_git", fake_git)
    monkeypatch.setattr(
        checker,
        "_git_bytes",
        lambda *args: f"object abc\ntype commit\ntag {tag}\n\nCCE {tag}".encode(),
    )
    with pytest.raises(SystemExit, match="must carry a PGP or SSH signature"):
        checker.main([tag], release_git=object())


def test_release_rejects_signed_tag_object_aliased_under_another_name(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    version = runtime_package.__version__
    monkeypatch.setattr(
        checker, "_verify_release_metadata", lambda name: version)

    def fake_git(*args):
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        raise AssertionError(args)

    monkeypatch.setattr(checker, "_git", fake_git)
    monkeypatch.setattr(
        checker,
        "_git_bytes",
        lambda *args: (
            "object abc\ntype commit\ntag v0.0.9\ntagger Maintainer "
            "<maintainer@example.test> 0 +0000\n\nrelease\n"
            "-----BEGIN SSH SIGNATURE-----"
        ).encode(),
    )
    with pytest.raises(SystemExit, match="signed tag object names"):
        checker.main([f"v{version}"], release_git=object())


def _trusted_check_api(commit, *, ci_path=".github/workflows/ci.yml"):
    repository = "owner/repository"
    expected = {
        "100": ("ci", ci_path),
        "101": ("attribution", ".github/workflows/no-ai-attribution.yml"),
        "102": ("secrets", ".github/workflows/secret-scan.yml"),
    }
    completed_at = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z")
    )
    checks = [
        {
            "id": int(run_id),
            "name": name,
            "head_sha": commit,
            "status": "completed",
            "conclusion": "success",
            "completed_at": completed_at,
            "app": {"id": 15368},
            "details_url": (
                f"https://github.com/{repository}/actions/runs/{run_id}/job/{run_id}0"
            ),
        }
        for run_id, (name, _) in expected.items()
    ]

    def request(path):
        if "/check-runs?" in path:
            return {"check_runs": checks}
        run_id = path.rsplit("/", 1)[-1]
        _, workflow_path = expected[run_id]
        return {
            "head_sha": commit,
            "path": workflow_path,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
        }

    return repository, request


def test_release_check_query_explicitly_requests_latest_runs(monkeypatch):
    checker = _load_release_script("check_release_tag")
    requested = []

    def request(path):
        requested.append(path)
        return {"check_runs": []}

    monkeypatch.setattr(checker, "_github_json", request)
    assert checker._check_runs("owner/repository", "a" * 40) == []
    assert requested == [
        "repos/owner/repository/commits/" + "a" * 40
        + "/check-runs?filter=latest&per_page=100&page=1"
    ]


def test_release_requires_exact_sha_checks_from_expected_actions_workflows(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "a" * 40
    repository, request = _trusted_check_api(commit)
    monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setattr(checker, "_github_json", request)

    checker._verify_required_checks(commit)


def test_release_rejects_same_named_check_from_wrong_workflow(monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "b" * 40
    repository, request = _trusted_check_api(
        commit, ci_path=".github/workflows/spoof-ci.yml")
    monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setattr(checker, "_github_json", request)

    with pytest.raises(SystemExit, match="ci from .github/workflows/ci.yml"):
        checker._verify_required_checks(commit)


def test_release_workflow_builds_read_only_before_publish_credentials():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    verify = workflow.split("\n  verify:", 1)[1].split("\n  structural:", 1)[0]
    structural = workflow.split("\n  structural:", 1)[1].split("\n  behavior:", 1)[0]
    behavior = workflow.split("\n  behavior:", 1)[1].split("\n  publish:", 1)[0]
    publish = workflow.split("\n  publish:", 1)[1].split("\n  pypi:", 1)[0]

    assert "git merge-base --is-ancestor HEAD refs/remotes/origin/main" in verify
    assert "--verify-required-checks" in verify
    assert "Run every release gate and build the candidate twice" in verify
    assert "contents: write" not in verify
    assert "id-token: write" not in verify
    assert "artifact-digest: ${{ steps.upload.outputs.artifact-digest }}" in verify
    assert "artifact-id: ${{ steps.upload.outputs.artifact-id }}" in verify

    assert "needs: verify" in structural
    assert "--structure-only" in structural
    assert "--behavior-only" not in structural

    assert "needs: [verify, structural]" in behavior
    assert "--behavior-only" in behavior
    assert "permissions: {}" in behavior
    assert "actions/checkout@" not in behavior
    assert "id-token: write" not in behavior
    assert "actions/upload-artifact@" not in behavior

    assert "needs: [verify, structural, behavior]" in publish
    assert "Run every release gate and build the candidate twice" not in publish
    assert "actions/checkout@" not in publish
    assert "actions/setup-python@" not in publish
    assert ".github/scripts/" not in publish
    assert "artifact-ids: ${{ needs.verify.outputs.artifact-id }}" in publish
    assert "digest-mismatch: error" in publish
    assert "cmp --silent" in publish
    assert publish.index("cmp --silent") < publish.index("GH_TOKEN:")
    assert "GH_REPO: ${{ github.repository }}" in publish
    assert publish.index("GH_REPO:") < publish.index("gh release create")


def test_local_attribution_hooks_use_the_ci_expression():
    workflow = (
        ROOT / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    pattern_line = next(
        line.strip() for line in workflow.splitlines()
        if line.strip().startswith("PATTERN='")
    )
    pattern = pattern_line.removeprefix("PATTERN='").removesuffix("'")

    for hook_name in ("pre-commit", "commit-msg"):
        hook = (ROOT / ".githooks" / hook_name).read_text(encoding="utf-8")
        assert f"PATTERN='{pattern}'" in hook
    assert "git grep --cached" in (
        ROOT / ".githooks" / "pre-commit"
    ).read_text(encoding="utf-8")
