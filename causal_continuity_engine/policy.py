"""Evidence-based autonomy policy engine (AUT-001..AUT-005, ADR-006).

Deterministic policy-as-code: the decision is a pure function of stored
state (tenant config, grants, downgrades, evidence) and the action request.
Nothing in the request can force an allow — deny by default, and agent
output cannot override a deny (AUT-003).

Levels: 0 observe, 1 recommend, 2 reversible execution, 3 guarded repository
action, 4 irreversible/external (prohibited in MVP, ADR-009).
"""

from __future__ import annotations

import math
from copy import deepcopy
from fnmatch import fnmatchcase

from .core import (
    canonical_json,
    parse_ts,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)
from .evidence import GRADES, normalize_artifact_paths
from .ontology import MVP_MAX_AUTONOMY
from .store import serialized_access
from .verifiers import (
    MAX_VERIFIER_TIMEOUT_SECONDS,
    VerifierSpec,
    check_command_safety,
)

_POLICY_SCHEMA = """
CREATE TABLE IF NOT EXISTS autonomy_grants (
    grant_id   TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    level      INTEGER NOT NULL,
    scope      TEXT,
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    reason     TEXT
);
CREATE TABLE IF NOT EXISTS autonomy_downgrades (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    ceiling    INTEGER NOT NULL,
    trigger    TEXT NOT NULL,
    at         TEXT NOT NULL,
    cleared_at TEXT,
    cleared_by TEXT
);
CREATE TABLE IF NOT EXISTS project_policy (
    project_id TEXT PRIMARY KEY,
    config     TEXT NOT NULL,
    tracked_ref_revision INTEGER NOT NULL DEFAULT 0
);
"""

DOWNGRADE_TRIGGERS = {
    "migration", "anomalous_behavior", "failed_proof", "major_invalidation",
    "expired_approval", "policy_violation",
}

# Action risk classes: reversibility drives the minimum level needed.
ACTION_CLASSES = {
    "observe": 0,
    "recommend": 1,
    "compose_packet": 1,
    "run_verifier": 2,
    "create_local_artifact": 2,
    "reversible_tool": 2,
    "create_branch": 3,
    "create_pr": 3,
    "update_pr": 3,
    "post_check": 3,
    "post_comment": 3,
    "merge": 4,
    "deploy": 4,
    "production_write": 4,
    "external_irreversible": 4,
}

DEFAULT_CONFIG = {
    "max_autonomy_level": 2,
    "require_proof_for": ["task_complete", "pr_ready"],
    # Each entry is either a bare name (UNPINNED — the claimant chooses what
    # runs under that name, which is not evidence) or a closed definition.
    # Subprocess kinds pin an absolute command; the built-in file-digest kind
    # pins its exact path/digest map and forbids a command.
    "required_verifiers": [],
    "guarded_pr_enabled": False,
    # Minimum evidence grade a completion proof must earn (ADR-027).
    # Defaults to C, which REFUSES grade D — a required check whose command
    # the claimant supplied. Safe by default: an unpinned required verifier
    # is not evidence, so a project must either pin its commands or lower
    # this deliberately. Set to None to disable the gate entirely.
    "min_evidence_grade": "C",
    # GitHub check runs are authoritative only when their producer's immutable
    # numeric App id is registered. A slug is an optional second check, never
    # the identity. An empty registry is deliberately fail closed.
    "trusted_verifier_apps": [],
    # workflow_run lacks a Checks App object. Trust it only by the stable
    # numeric workflow id, optionally also pinning its repository path.
    # Actor/sender login is provenance, never verifier identity.
    "trusted_workflows": [],
    # GitHub push events use the full ref. The default follows GitHub's modern
    # repository default without trusting the first webhook to choose a
    # security frontier. Set None only to leave revision continuity explicitly
    # undecidable until a ref is configured or a legacy pinned ref exists.
    "tracked_ref": "refs/heads/main",
    # Whether prose may mandate. AD-006 already refuses a mandate from an
    # untrusted source; this extends the same refusal to every source when a
    # project would rather its authority be declared than inferred. Published
    # measurements put rule-based requirements extraction near F1 0.14, so a
    # statement pulled out of an issue body is a proposal about intent, and a
    # project may reasonably decline to let one bind anything. Default True
    # preserves existing behaviour exactly; a project opts in.
    "prose_may_mandate": True,
}

# Stable trust-state marker for a policy that demands proof but defines no
# verifier capable of establishing it. This lives at the policy boundary so
# every consumer reports the same fail-closed state.
PROOF_REQUIRED_WITHOUT_VERIFIERS = (
    "policy:proof-required-without-required-verifiers")


def proof_policy_verifier_gaps(
        config: dict, verifier_definitions: list[dict]) -> list[str]:
    """Return fail-closed gaps implied by proof/verifier policy itself."""
    if config.get("require_proof_for") and not verifier_definitions:
        return [PROOF_REQUIRED_WITHOUT_VERIFIERS]
    return []

_VERIFIER_CONFIG_KEYS = {
    "name", "kind", "command", "expected_properties", "timeout_seconds",
    "expect_fail_command", "artifacts",
}
_WORKFLOW_CONFIG_KEYS = {"workflow_id", "path"}
_APP_CONFIG_KEYS = {"app_id", "slug"}
_REVERSIBILITY_CLASSES = {"reversible", "compensable", "irreversible"}


def _valid_autonomy_level(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 0 <= value <= MVP_MAX_AUTONOMY
    )


def _validate_probability(name: str, value):
    if (isinstance(value, bool)
            or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value))
            or not 0 <= value <= 1):
        raise ValueError(f"{name} must be a finite number from 0 to 1")


def _validate_actor(value: object, *, field: str) -> str:
    actor = validate_human_text(value, field=field)
    if not actor.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return actor


def _normalise_trusted_apps(value) -> list[dict]:
    """Return immutable GitHub App identities or reject the whole registry.

    A legacy list of slugs is intentionally not migrated implicitly: slugs
    can be renamed or reused and therefore cannot identify the producer an
    operator meant to trust. Old persisted rows are handled fail-closed by
    ``trusted_verifier_apps`` until an operator supplies numeric App ids.
    """
    if not isinstance(value, list):
        raise ValueError("trusted_verifier_apps must be an array")
    normalised = []
    seen: dict[int, str | None] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError(
                "trusted_verifier_apps entries must be objects with a "
                "positive app_id; legacy slug-only entries fail closed")
        unknown = sorted(set(entry) - _APP_CONFIG_KEYS)
        if unknown:
            raise ValueError(
                f"unknown trusted_verifier_apps field(s): {unknown}")
        app_id = entry.get("app_id")
        if (isinstance(app_id, bool) or not isinstance(app_id, int)
                or app_id <= 0):
            raise ValueError(
                "trusted_verifier_apps app_id must be a positive integer")
        slug = entry.get("slug")
        if slug is not None:
            if not isinstance(slug, str) or not slug.strip():
                raise ValueError(
                    "trusted_verifier_apps slug must be a non-empty string")
            slug = slug.strip()
        if app_id in seen:
            if seen[app_id] != slug:
                raise ValueError(
                    f"trusted_verifier_apps has conflicting entries for "
                    f"app_id {app_id}")
            continue
        seen[app_id] = slug
        item = {"app_id": app_id}
        if slug is not None:
            item["slug"] = slug
        normalised.append(item)
    return normalised


class PolicyEngine:
    def __init__(
            self, store, tenant_max_level: int = MVP_MAX_AUTONOMY, *,
            graph=None, tenant_id: str | None = None):
        self.store = store
        self._conn = store._conn
        self._lock = store._lock
        self.graph = graph
        self.tenant_id = tenant_id
        self.tenant_max_level = min(tenant_max_level, MVP_MAX_AUTONOMY)
        with self._lock:
            self._conn.executescript(_POLICY_SCHEMA)
        # Separate Engine instances have separate Python locks, so the
        # inspect/ALTER migration must also be serialized by SQLite.  Re-read
        # the schema only after BEGIN IMMEDIATE wins the database write lock;
        # otherwise two first-openers can both decide the column is absent.
        with self.store.transaction():
            policy_columns = {
                row["name"] for row in self._conn.execute(
                    "PRAGMA table_info(project_policy)")}
            if "tracked_ref_revision" not in policy_columns:
                self._conn.execute(
                    "ALTER TABLE project_policy ADD COLUMN "
                    "tracked_ref_revision INTEGER NOT NULL DEFAULT 0")

    def _require_project(self, project_id: str) -> None:
        validate_public_identifier(project_id, field="project_id")
        if self.tenant_id is None:
            return
        if self.graph is None:
            raise PermissionError("tenant-bound policy has no project registry")
        try:
            self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
        except KeyError:
            raise PermissionError(
                f"policy project {project_id!r} is outside tenant "
                f"{self.tenant_id!r}") from None

    # ----------------------------------------------------------------- config

    @staticmethod
    def validate_project_config(config: dict) -> dict:
        """Validate and normalize the complete persisted policy document.

        This is deliberately a PolicyEngine boundary rather than a CLI
        schema: every caller that can persist control state gets the same
        fail-closed contract. Verifier commands are parsed and safety-checked
        here but are never executed during configuration.
        """
        if not isinstance(config, dict):
            raise ValueError("project policy must be a JSON object")
        unknown = sorted(set(config) - set(DEFAULT_CONFIG))
        if unknown:
            raise ValueError(f"unknown project policy field(s): {unknown}")
        merged = {**DEFAULT_CONFIG, **config}

        level = merged["max_autonomy_level"]
        if (isinstance(level, bool) or not isinstance(level, int)
                or not 0 <= level <= MVP_MAX_AUTONOMY):
            raise ValueError(
                f"max_autonomy_level must be an integer from 0 to "
                f"{MVP_MAX_AUTONOMY}")

        proof_types = merged["require_proof_for"]
        if (not isinstance(proof_types, list)
                or any(not isinstance(value, str) or not value.strip()
                       for value in proof_types)):
            raise ValueError(
                "require_proof_for must be a list of non-empty claim types")
        merged["require_proof_for"] = list(dict.fromkeys(
            value.strip() for value in proof_types))

        verifier_entries = merged["required_verifiers"]
        if not isinstance(verifier_entries, list):
            raise ValueError("required_verifiers must be an array")
        normalised_verifiers = []
        verifier_names = set()
        for entry in verifier_entries:
            if isinstance(entry, str):
                name = entry.strip()
                if not name:
                    raise ValueError(
                        "required_verifiers names must be non-empty strings")
                normalised = name
            elif isinstance(entry, dict):
                unknown_fields = sorted(set(entry) - _VERIFIER_CONFIG_KEYS)
                if unknown_fields:
                    raise ValueError(
                        f"unknown required_verifiers field(s): {unknown_fields}")
                name = entry.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise ValueError(
                        "required_verifiers entries need a non-empty name")
                name = name.strip()
                normalised = {"name": name}

                kind = entry.get("kind", "command")
                if not isinstance(kind, str):
                    raise ValueError("verifier kind must be a string")
                normalised["kind"] = kind

                command = entry.get("command")
                if command is not None:
                    if not isinstance(command, str) or not command.strip():
                        raise ValueError(
                            "verifier command must be a non-empty string or null")
                    check_command_safety(command, require_absolute=True)
                    normalised["command"] = command
                elif "command" in entry:
                    normalised["command"] = None

                expected = entry.get("expected_properties", {})
                if not isinstance(expected, dict):
                    raise ValueError(
                        "verifier expected_properties must be an object")
                if "expected_properties" in entry:
                    normalised["expected_properties"] = expected

                timeout = entry.get("timeout_seconds", 300)
                if (isinstance(timeout, bool) or not isinstance(timeout, int)
                        or not 1 <= timeout <= MAX_VERIFIER_TIMEOUT_SECONDS):
                    raise ValueError(
                        "verifier timeout_seconds must be an integer from 1 "
                        f"to {MAX_VERIFIER_TIMEOUT_SECONDS}")
                if "timeout_seconds" in entry:
                    normalised["timeout_seconds"] = timeout

                control = entry.get("expect_fail_command")
                if control is not None:
                    if not isinstance(control, str) or not control.strip():
                        raise ValueError(
                            "expect_fail_command must be a non-empty string or null")
                    check_command_safety(control, require_absolute=True)
                    normalised["expect_fail_command"] = control
                elif "expect_fail_command" in entry:
                    normalised["expect_fail_command"] = None

                artifacts = normalize_artifact_paths(
                    entry.get("artifacts", []))
                if "artifacts" in entry:
                    normalised["artifacts"] = artifacts

                # Constructor validation pins the accepted verifier-kind
                # vocabulary without running the command.
                spec = VerifierSpec.from_policy(normalised)
                if spec.kind == "file-digest":
                    if not spec.artifacts:
                        raise ValueError(
                            "policy file-digest verifiers must declare at "
                            "least one expected file digest")
                    normalised["expected_properties"] = spec.expected_properties
                    normalised["artifacts"] = spec.artifacts
                elif spec.kind == "value-oracle":
                    if not spec.expected_properties.get("values"):
                        raise ValueError(
                            "policy value-oracle verifiers must declare at "
                            "least one expected value")
                    normalised["expected_properties"] = spec.expected_properties
            else:
                raise ValueError(
                    "required_verifiers entries must be names or objects")
            if name in verifier_names:
                raise ValueError(
                    f"required_verifiers contains duplicate name {name!r}")
            verifier_names.add(name)
            normalised_verifiers.append(normalised)
        merged["required_verifiers"] = normalised_verifiers

        guarded = merged["guarded_pr_enabled"]
        if not isinstance(guarded, bool):
            raise ValueError("guarded_pr_enabled must be a boolean")

        prose_mandate = merged["prose_may_mandate"]
        if not isinstance(prose_mandate, bool):
            raise ValueError("prose_may_mandate must be a boolean")

        minimum = merged["min_evidence_grade"]
        if (minimum is not None
                and (not isinstance(minimum, str) or minimum not in GRADES)):
            raise ValueError(
                f"min_evidence_grade must be one of {GRADES!r} or null")

        merged["trusted_verifier_apps"] = _normalise_trusted_apps(
            merged["trusted_verifier_apps"])

        trusted_workflows = merged["trusted_workflows"]
        if not isinstance(trusted_workflows, list):
            raise ValueError("trusted_workflows must be an array")
        normalised_workflows = []
        seen_workflows = set()
        for entry in trusted_workflows:
            if not isinstance(entry, dict):
                raise ValueError(
                    "trusted_workflows entries must be objects with workflow_id")
            unknown_fields = sorted(set(entry) - _WORKFLOW_CONFIG_KEYS)
            if unknown_fields:
                raise ValueError(
                    f"unknown trusted_workflows field(s): {unknown_fields}")
            workflow_id = entry.get("workflow_id")
            path = entry.get("path")
            if (isinstance(workflow_id, bool)
                    or not isinstance(workflow_id, int)
                    or workflow_id <= 0):
                raise ValueError("trusted workflow_id must be a positive integer")
            if path is not None:
                if (not isinstance(path, str) or not path.strip()
                        or not path.replace("\\", "/").startswith(
                            ".github/workflows/")
                        or ".." in path.replace("\\", "/").split("/")):
                    raise ValueError(
                        "trusted workflow path must be under .github/workflows")
                path = path.replace("\\", "/")
            key = (workflow_id, path)
            if key not in seen_workflows:
                normalised_workflows.append({
                    "workflow_id": workflow_id, "path": path})
                seen_workflows.add(key)
        merged["trusted_workflows"] = normalised_workflows

        tracked_ref = merged["tracked_ref"]
        if tracked_ref is not None:
            invalid_ref = (
                not isinstance(tracked_ref, str)
                or not tracked_ref.startswith("refs/heads/")
                or tracked_ref == "refs/heads/"
                or "\\" in tracked_ref
                or ".." in tracked_ref
                or "@{" in tracked_ref
                or "//" in tracked_ref
                or tracked_ref.endswith(("/", "."))
                or any(char.isspace() or ord(char) < 32 for char in tracked_ref)
            )
            if invalid_ref:
                raise ValueError(
                    "tracked_ref must be null or a full refs/heads/... Git ref")

        try:
            canonical_json(merged)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"project policy must contain RFC 8785 I-JSON values: {exc}") from None
        return merged

    def set_project_config(self, project_id: str, config: dict, actor: str = "cce"):
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id must be a non-empty string")
        self._require_project(project_id)
        merged = self.validate_project_config(config)
        serialized = canonical_json(merged)
        with self.store.transaction():
            previous = self._conn.execute(
                "SELECT config, tracked_ref_revision FROM project_policy "
                "WHERE project_id = ?", (project_id,)).fetchone()
            revision = previous["tracked_ref_revision"] if previous else 0
            previous_ref = None
            if previous is not None:
                try:
                    previous_ref = strict_json_loads(previous["config"]).get(
                        "tracked_ref")
                except (AttributeError, TypeError, ValueError):
                    # Corrupt prior control state cannot preserve authority.
                    previous_ref = object()
            if previous is None or previous_ref != merged["tracked_ref"]:
                revision += 1
            self._conn.execute(
                "INSERT INTO project_policy "
                "(project_id, config, tracked_ref_revision) VALUES (?,?,?) "
                "ON CONFLICT(project_id) DO UPDATE SET config = excluded.config, "
                "tracked_ref_revision = excluded.tracked_ref_revision",
                (project_id, serialized, revision))
            self.store.audit(
                actor=actor, action="policy.config", object_id=project_id,
                detail=serialized)

    @serialized_access
    def project_config(self, project_id: str) -> dict:
        self._require_project(project_id)
        row = self._conn.execute(
            "SELECT config FROM project_policy WHERE project_id = ?",
            (project_id,)).fetchone()
        # DEFAULT_CONFIG contains lists. A shallow copy lets one caller
        # mutate the process-wide default and silently weaken every project
        # created afterwards.
        return strict_json_loads(row["config"]) if row else deepcopy(DEFAULT_CONFIG)

    @serialized_access
    def tracked_ref_basis(self, project_id: str) -> dict:
        """Protected ref plus monotonic epoch; heads are valid only for both."""
        self._require_project(project_id)
        row = self._conn.execute(
            "SELECT config, tracked_ref_revision FROM project_policy "
            "WHERE project_id = ?", (project_id,)).fetchone()
        if row is None:
            return {"tracked_ref": deepcopy(DEFAULT_CONFIG)["tracked_ref"],
                    "revision": 0}
        revision = row["tracked_ref_revision"]
        if (isinstance(revision, bool) or not isinstance(revision, int)
                or revision < 0):
            raise ValueError("tracked-ref policy revision is malformed")
        try:
            tracked_ref = strict_json_loads(row["config"])["tracked_ref"]
        except (KeyError, TypeError, ValueError):
            raise ValueError("tracked-ref policy state is malformed") from None
        return {"tracked_ref": tracked_ref, "revision": revision}

    @serialized_access
    def tracked_ref_frontier(
            self, project_id: str, project_data: dict) -> dict:
        """Resolve the only revision frontier external checks may satisfy.

        A stored SHA belongs to the protected-ref policy epoch under which it
        was observed.  Changing/unsetting that ref, receiving an out-of-order
        deletion, or otherwise marking the frontier uncertain makes the SHA
        useful as history but not as a current trust anchor.
        """
        if not isinstance(project_data, dict):
            raise ValueError("project frontier state must be an object")
        basis = self.tracked_ref_basis(project_id)
        tracked_ref = basis["tracked_ref"]
        matches_policy = (
            tracked_ref is not None
            and project_data.get("tracked_ref") == tracked_ref
            and project_data.get("tracked_ref_revision") == basis["revision"]
        )
        stored_head = project_data.get("current_head_sha")
        current_head = stored_head if (
            matches_policy
            and isinstance(stored_head, str)
            and bool(stored_head)
        ) else None
        uncertain = (
            bool(project_data.get("revision_frontier_uncertain"))
            if matches_policy else bool(project_data.get("repository_id"))
        )
        return {
            "tracked_ref": tracked_ref,
            "revision": basis["revision"],
            "matches_policy": matches_policy,
            "current_head_sha": current_head,
            "uncertain": uncertain,
            "trusted_external_head_sha": (
                current_head if current_head and not uncertain else None),
        }

    def required_verifiers(self, project_id: str) -> list[str]:
        """Names of the verifiers this project mandates."""
        return [self._verifier_name(v) for v
                in self.project_config(project_id).get("required_verifiers", [])]

    def required_verifier_defs(self, project_id: str) -> list[dict]:
        """The mandated verifiers as declarations.

        A pinned subprocess entry carries the command policy says must run.
        A pinned file-digest entry carries a closed path/digest map executed
        by the built-in adapter. A bare name carries neither and remains
        claimant-satisfiable and unpinned (ADR-024).
        """
        out = []
        for entry in self.project_config(project_id).get("required_verifiers", []):
            if isinstance(entry, str):
                out.append({"name": entry, "command": None, "pinned": False})
            elif isinstance(entry, dict) and entry.get("name"):
                spec = VerifierSpec.from_policy(entry)
                normalised = {
                    **entry,
                    "kind": spec.kind,
                    "command": spec.command,
                    "expected_properties": spec.expected_properties,
                    "timeout_seconds": spec.timeout_seconds,
                    "artifacts": spec.artifacts,
                    "pinned": spec.pinned,
                }
                out.append(normalised)
            else:
                raise ValueError(f"malformed required_verifiers entry: {entry!r}")
        return out

    @staticmethod
    def _verifier_name(entry) -> str:
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict) and entry.get("name"):
            return entry["name"]
        raise ValueError(f"malformed required_verifiers entry: {entry!r}")

    def unpinned_required_verifiers(self, project_id: str) -> list[str]:
        return [d["name"] for d in self.required_verifier_defs(project_id)
                if not d["pinned"]]

    def min_evidence_grade(self, project_id: str) -> str | None:
        return self.project_config(project_id).get("min_evidence_grade")

    def trusted_verifier_apps(self, project_id: str) -> list[dict]:
        """Immutable GitHub App identities allowed to produce check results.

        Legacy slug-only rows return an empty registry. Availability is less
        damaging than silently authorizing a mutable display name.
        """
        value = self.project_config(project_id).get("trusted_verifier_apps", [])
        try:
            return _normalise_trusted_apps(value)
        except ValueError:
            # The setter is not the deciding path for legacy or directly
            # edited rows, so validate again at the authorization boundary.
            return []

    def trusted_workflows(self, project_id: str) -> list[dict]:
        """Fail-closed workflow_run identities pinned by id and optional path."""
        value = self.project_config(project_id).get("trusted_workflows", [])
        if not isinstance(value, list):
            return []
        out = []
        for entry in value:
            if not isinstance(entry, dict):
                return []
            workflow_id = entry.get("workflow_id")
            path = entry.get("path")
            if (isinstance(workflow_id, bool)
                    or not isinstance(workflow_id, int)
                    or workflow_id <= 0
                    or (path is not None and not isinstance(path, str))):
                return []
            out.append({"workflow_id": workflow_id, "path": path})
        return out

    def external_verifier_trusted(
            self, project_id: str, source: str, provenance: dict) -> bool:
        """Evaluate a GitHub producer against current project policy."""
        if source == "github:workflow_run":
            workflow_id = provenance.get("workflow_id")
            path = provenance.get("workflow_path")
            return any(
                entry["workflow_id"] == workflow_id
                and (entry.get("path") is None or entry.get("path") == path)
                for entry in self.trusted_workflows(project_id)
            )
        app_id = provenance.get("app_id")
        slug = provenance.get("app")
        if (isinstance(app_id, bool) or not isinstance(app_id, int)
                or app_id <= 0):
            return False
        return any(
            entry["app_id"] == app_id
            and ("slug" not in entry or entry["slug"] == slug)
            for entry in self.trusted_verifier_apps(project_id))

    # ----------------------------------------------------------------- grants

    @staticmethod
    def _normalise_scope(value: str | None) -> str | None:
        if value is None:
            return None
        normalised = value.replace("\\", "/").strip()
        parts = normalised.split("/")
        if (not normalised or normalised.startswith("/") or ".." in parts
                or (parts and ":" in parts[0])):
            return None
        return normalised

    def grant(self, *, project_id: str, level: int, granted_by: str,
              scope: str | None = None, expires_at: str | None = None,
              reason: str | None = None) -> str:
        from .core import new_id
        self._require_project(project_id)
        if not _valid_autonomy_level(level):
            raise ValueError(
                f"grant level must be an integer from 0 to "
                f"{MVP_MAX_AUTONOMY}")
        granted_by = _validate_actor(granted_by, field="granted_by")
        if reason is not None:
            validate_human_text(
                reason, field="grant reason", max_length=4096)
        if expires_at is not None:
            if not isinstance(expires_at, str) or not expires_at.strip():
                raise ValueError(
                    "grant expires_at must be an ISO-8601 timestamp or None")
            try:
                parse_ts(expires_at)
            except (ValueError, OverflowError):
                raise ValueError(
                    "grant expires_at must be an ISO-8601 timestamp or None"
                ) from None
        if scope is not None and (not isinstance(scope, str) or not scope.strip()):
            raise ValueError("grant scope must be a non-empty path glob or None")
        normalised_scope = self._normalise_scope(scope)
        if scope is not None and normalised_scope is None:
            raise ValueError("grant scope must be a project-relative path glob")
        scope = normalised_scope
        gid = new_id("grant")
        with self.store.transaction():
            self._conn.execute(
                "INSERT INTO autonomy_grants (grant_id, project_id, level, scope,"
                " granted_by, granted_at, expires_at, reason) VALUES (?,?,?,?,?,?,?,?)",
                (gid, project_id, level, scope, granted_by, utcnow(), expires_at, reason))
            self.store.audit(
                actor=granted_by, action="policy.grant", object_id=gid,
                authority="human_decision",
                detail=f"level {level} scope={scope} expires={expires_at}")
        return gid

    def revoke(self, grant_id: str, actor: str, reason: str = ""):
        validate_public_identifier(grant_id, field="grant_id")
        actor = _validate_actor(actor, field="revocation actor")
        if not isinstance(reason, str):
            raise ValueError("revocation reason must be a string")
        if reason:
            validate_human_text(
                reason, field="revocation reason", max_length=4096)
        with self.store.transaction():
            row = self._conn.execute(
                "SELECT project_id FROM autonomy_grants WHERE grant_id = ?",
                (grant_id,)).fetchone()
            if row is None:
                raise KeyError(grant_id)
            self._require_project(row["project_id"])
            self._conn.execute(
                "UPDATE autonomy_grants SET revoked_at = ? WHERE grant_id = ?",
                (utcnow(), grant_id))
            self.store.audit(
                actor=actor, action="policy.revoke", object_id=grant_id,
                detail=reason)

    @serialized_access
    def active_grants(self, project_id: str, now: str | None = None) -> list[dict]:
        self._require_project(project_id)
        now = utcnow() if now is None else now
        try:
            current = parse_ts(now)
        except (AttributeError, TypeError, ValueError, OverflowError):
            raise ValueError("now must be an ISO-8601 timestamp") from None
        rows = self._conn.execute(
            "SELECT * FROM autonomy_grants WHERE project_id = ? AND revoked_at IS NULL",
            (project_id,)).fetchall()
        out = []
        for r in rows:
            level = r["level"]
            actor = r["granted_by"]
            scope = r["scope"]
            expiry = r["expires_at"]
            if (not _valid_autonomy_level(level)
                    or not isinstance(actor, str) or not actor.strip()
                    or (scope is not None
                        and (not isinstance(scope, str)
                             or self._normalise_scope(scope) is None))):
                continue
            if expiry is not None:
                if not isinstance(expiry, str) or not expiry.strip():
                    continue
                try:
                    if parse_ts(expiry) <= current:
                        continue
                except (ValueError, OverflowError):
                    # A directly edited malformed grant is never authority.
                    continue
            out.append(dict(r))
        return out

    # -------------------------------------------------------------- downgrade

    def downgrade(self, project_id: str, trigger: str, ceiling: int = 1,
                  actor: str = "cce"):
        """AUT-005: automatic conservative downgrade."""
        self._require_project(project_id)
        if not isinstance(trigger, str) or trigger not in DOWNGRADE_TRIGGERS:
            raise ValueError(f"unknown downgrade trigger {trigger!r}")
        if not _valid_autonomy_level(ceiling):
            raise ValueError(
                f"downgrade ceiling must be an integer from 0 to "
                f"{MVP_MAX_AUTONOMY}")
        actor = _validate_actor(actor, field="downgrade actor")
        with self.store.transaction():
            self._conn.execute(
                "INSERT INTO autonomy_downgrades (project_id, ceiling, trigger, at)"
                " VALUES (?,?,?,?)", (project_id, ceiling, trigger, utcnow()))
            self.store.audit(
                actor=actor, action="policy.downgrade", object_id=project_id,
                detail=f"{trigger} -> ceiling {ceiling}")

    def clear_downgrades(self, project_id: str, actor: str):
        self._require_project(project_id)
        actor = _validate_actor(actor, field="clear actor")
        with self.store.transaction():
            self._conn.execute(
                "UPDATE autonomy_downgrades SET cleared_at = ?, cleared_by = ?"
                " WHERE project_id = ? AND cleared_at IS NULL",
                (utcnow(), actor, project_id))
            self.store.audit(
                actor=actor, action="policy.clear_downgrades",
                object_id=project_id, authority="human_decision")

    @serialized_access
    def active_downgrade_ceiling(self, project_id: str) -> int | None:
        self._require_project(project_id)
        rows = self._conn.execute(
            "SELECT ceiling FROM autonomy_downgrades WHERE project_id = ?"
            " AND cleared_at IS NULL", (project_id,)).fetchall()
        if not rows:
            return None
        ceilings = []
        for row in rows:
            ceiling = row["ceiling"]
            if not _valid_autonomy_level(ceiling):
                # Corruption must tighten authorization, never erase a live
                # downgrade or turn it into an elevation.
                return 0
            ceilings.append(ceiling)
        return min(ceilings)

    # ----------------------------------------------------------------- decide

    @staticmethod
    def _scope_matches(grant_scope: str | None, action_scope: str | None) -> bool:
        if grant_scope is None:
            return True
        if not isinstance(action_scope, str) or not action_scope.strip():
            return False
        pattern = PolicyEngine._normalise_scope(grant_scope)
        target = PolicyEngine._normalise_scope(action_scope)
        if pattern is None or target is None:
            return False
        return fnmatchcase(target, pattern)

    @serialized_access
    def effective_level(self, project_id: str, now: str | None = None,
                        action_scope: str | None = None) -> int:
        config = self.project_config(project_id)
        level = 0  # default observe for a new project (AUT-001)
        grants = [g for g in self.active_grants(project_id, now)
                  if self._scope_matches(g.get("scope"), action_scope)]
        if grants:
            level = max(g["level"] for g in grants)
        level = min(level, int(config["max_autonomy_level"]), self.tenant_max_level)
        ceiling = self.active_downgrade_ceiling(project_id)
        if ceiling is not None:
            level = min(level, ceiling)
        return level

    @serialized_access
    def decide(
        self,
        *,
        project_id: str,
        action_type: str,
        reversibility: str = "reversible",     # reversible | compensable | irreversible
        evidence_quality: float = 0.5,          # 0..1 from proof/verification state
        blast_radius: int = 0,
        historical_reliability: float = 0.5,
        action_scope: str | None = None,
        now: str | None = None,
    ) -> dict:
        """Deterministic authorization decision (AUT-002/AUT-003).

        Returns {decision, effective_level, required_level, reasons, ...}.
        The caller cannot supply anything that turns a deny into an allow:
        every input can only make the decision stricter or provide the
        action's classification.
        """
        if (not isinstance(reversibility, str)
                or reversibility not in _REVERSIBILITY_CLASSES):
            raise ValueError(
                "reversibility must be reversible, compensable, or "
                "irreversible")
        _validate_probability("evidence_quality", evidence_quality)
        _validate_probability(
            "historical_reliability", historical_reliability)
        if (isinstance(blast_radius, bool)
                or not isinstance(blast_radius, int)
                or blast_radius < 0):
            raise ValueError("blast_radius must be a non-negative integer")
        if not isinstance(action_type, str):
            raise ValueError("action_type must be a string")

        reasons: list[str] = []
        config = self.project_config(project_id)
        required_level = ACTION_CLASSES.get(action_type)
        if required_level is None:
            required_level = 4
            reasons.append(f"unknown action type {action_type!r}: treated as irreversible")
        if reversibility == "irreversible" and required_level < 4:
            required_level = 4
            reasons.append("irreversible action forced to level 4")
        if blast_radius >= 20 and required_level < 3:
            required_level = 3
            reasons.append(f"blast radius {blast_radius} raises required level to 3")
        if evidence_quality < 0.4 and required_level >= 2:
            required_level = max(required_level, 3)
            reasons.append("low evidence quality raises the bar")
        if historical_reliability < 0.3 and required_level >= 2:
            required_level = max(required_level, 3)
            reasons.append("poor historical reliability raises the bar")

        active_grants = self.active_grants(project_id, now)
        applicable_grants = [g for g in active_grants
                             if self._scope_matches(g.get("scope"), action_scope)]
        effective = self.effective_level(project_id, now, action_scope)
        if required_level >= 4:
            decision = "deny"
            reasons.append("level 4 (irreversible/external) prohibited in MVP (ADR-009)")
        elif required_level == 3 and not config.get("guarded_pr_enabled") and \
                action_type in ("create_pr", "update_pr", "create_branch"):
            decision = "deny"
            reasons.append("guarded repository actions not enabled for this project")
        elif effective >= required_level:
            decision = "allow"
            reasons.append(f"effective level {effective} >= required {required_level}")
        else:
            decision = "deny"
            reasons.append(f"effective level {effective} < required {required_level}")
            ignored = sorted({g["scope"] for g in active_grants
                              if g.get("scope") is not None
                              and g not in applicable_grants})
            if ignored:
                reasons.append(
                    f"scoped grant(s) {ignored} do not cover action scope {action_scope!r}")

        result = {
            "decision": decision,
            "action_type": action_type,
            "required_level": required_level,
            "effective_level": effective,
            "action_scope": action_scope,
            "applicable_grant_ids": [g["grant_id"] for g in applicable_grants],
            "reasons": reasons,
            "policy_config": {"max_autonomy_level": config["max_autonomy_level"],
                              "tenant_max": self.tenant_max_level},
            "decided_at": utcnow(),
        }
        self.store.audit(actor="policy-engine", action="policy.decide",
                         object_id=project_id,
                         detail=f"{action_type}: {decision} ({'; '.join(reasons)})")
        return result

    def proof_required(self, project_id: str, claim_type: str) -> bool:
        return claim_type in self.project_config(project_id).get("require_proof_for", [])
