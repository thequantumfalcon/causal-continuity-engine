"""Mechanically checked capability claims (ADR-029).

`docs/REQUIREMENTS_COVERAGE.md` used to be hand-written prose. Nothing broke
if a cited test was renamed, and nothing objected when a row said
"implemented" for a gate a claimant could walk through — which is exactly
what happened to EV-004 before ADR-024.

Here every claim names the symbols that must import and the files and tests
that must exist, plus an `honest_limit` recording what the row does NOT mean.
`verify()` resolves all of it. A stale claim fails the build instead of
quietly reading well, and the markdown table is generated from these
declarations rather than maintained beside them.

This checks that claimed code EXISTS and its tests are present. It cannot
check that the code is correct — that is what the suite and ContinuityBench
are for. A capability audit is an anti-drift device, not an oracle.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import stat
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

STATUSES = ("implemented", "partial", "contract-only", "out-of-scope")

ROOT = Path(__file__).resolve().parent.parent

_AUDIT_DATA_PARTS = ("share", "causal-continuity-engine", "audit")
_OWNED_AUDIT_MODULES = {
    "verifiers.verify_proof": "verifiers/verify_proof.py",
}


@dataclass(frozen=True)
class Capability:
    requirement: str
    layer: str
    summary: str
    status: str
    honest_limit: str
    symbols: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"{self.requirement}: bad status {self.status!r}")
        if self.status == "implemented" and not (self.symbols and self.tests):
            raise ValueError(
                f"{self.requirement}: 'implemented' requires both importable "
                f"symbols and backing tests — otherwise it is prose")


def _resolve(symbol: str):
    """'causal_continuity_engine.graph:Graph.provenance' -> the attribute, or raise."""
    if not isinstance(symbol, str) or symbol.count(":") != 1:
        raise ValueError("symbol must use exact module:attribute syntax")
    module_name, attr_path = symbol.split(":", 1)
    module_parts = module_name.split(".")
    attr_parts = attr_path.split(".")
    if (not module_name or not attr_path
            or any(not part.isidentifier() for part in module_parts)
            or any(not part.isidentifier() for part in attr_parts)):
        raise ValueError(
            "symbol must use exact module:attribute syntax with a dotted "
            "attribute path")
    audit_relative = _OWNED_AUDIT_MODULES.get(module_name)
    if audit_relative is None:
        obj = importlib.import_module(module_name)
    else:
        location = _locate_evidence(audit_relative)
        if location is None:
            raise ImportError(
                f"owned audit module {module_name!r} is not available")
        private_name = f"{__package__}._audit_{location.stem}"
        spec = importlib.util.spec_from_file_location(private_name, location)
        if spec is None or spec.loader is None:
            raise ImportError(
                f"owned audit module {module_name!r} cannot be loaded")
        obj = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(obj)
    for part in attr_parts:
        obj = getattr(obj, part)
    return obj


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _physical_checkout_file(root: Path, parts: tuple[str, ...]) -> bool:
    """Require every evidence component to be physical and the leaf regular."""
    cursor = root
    try:
        root_info = os.lstat(cursor)
        if _is_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
            return False
        for index, part in enumerate(parts):
            cursor = cursor / part
            info = os.lstat(cursor)
            if _is_reparse(info):
                return False
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                return False
        return bool(parts) and stat.S_ISREG(info.st_mode)
    except (OSError, ValueError):
        return False


def _safe_evidence_parts(relative: str) -> tuple[str, ...] | None:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        return None
    normalized = relative.replace("\\", "/")
    parts = tuple(normalized.split("/"))
    path = Path(relative)
    if (path.is_absolute() or path.drive or path.anchor
            or any(part in {"", ".", ".."} for part in parts)):
        return None
    return parts


def _locate_evidence(relative: str) -> Path | None:
    """Locate physical audit evidence owned by this source or distribution."""
    parts = _safe_evidence_parts(relative)
    if parts is None:
        return None
    try:
        root = ROOT.resolve(strict=True)
        candidate = ROOT.joinpath(*parts)
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError):
        resolved = None
        root = None
    if (resolved is not None and root is not None
            and (resolved == root or root in resolved.parents)
            and _physical_checkout_file(ROOT, parts)):
        return resolved
    # A checkout is authoritative for its own audit. Falling through to an
    # older globally installed causal-continuity-engine would let a deleted
    # test or specification survive the gate using unrelated bytes.
    if (ROOT / "pyproject.toml").is_file():
        return None
    try:
        installed = distribution("causal-continuity-engine")
    except PackageNotFoundError:
        return None
    owned_suffix = _AUDIT_DATA_PARTS + parts
    for entry in installed.files or ():
        entry_parts = tuple(str(entry).replace("\\", "/").split("/"))
        if entry_parts[-len(owned_suffix):] != owned_suffix:
            continue
        try:
            located = Path(os.path.abspath(installed.locate_file(entry)))
            if tuple(located.parts[-len(owned_suffix):]) != owned_suffix:
                continue
            owned_parent = located.parents[len(owned_suffix) - 1]
            resolved = located.resolve(strict=True)
        except (IndexError, OSError, TypeError, ValueError):
            continue
        if _physical_checkout_file(owned_parent, owned_suffix):
            return resolved
    return None


def _evidence_exists(relative: str) -> bool:
    """Find audit evidence in a checkout or wherever the wheel installed it."""
    return _locate_evidence(relative) is not None


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        requirement="CCG-001", layer="Core",
        summary="Persist source events append-only with tamper evidence",
        status="implemented",
        honest_limit="Append-only is enforced by SQLite triggers and hash chains, "
                     "not immutable media. A database operator can disable local "
                     "controls or truncate a tail; an externally published anchor "
                     "is required to expose that. Idempotency is scoped to "
                     "(tenant_id, project_id, idempotency_key); a source that "
                     "reuses a key in that scope for genuinely different content "
                     "is flagged, not merged.",
        symbols=(
            "causal_continuity_engine.store:Store.append_event",
            "causal_continuity_engine.store:PayloadMismatchError",
        ),
        files=("causal_continuity_engine/store.py",), tests=("tests/test_store_graph.py",)),
    Capability(
        requirement="CCG-004", layer="Core", summary="Bi-temporal validity",
        status="implemented",
        honest_limit="Valid time is carried and queried; it is not inferred. A source "
                     "that misreports when a fact became true is believed.",
        symbols=(
            "causal_continuity_engine.graph:Graph.as_of",
            "causal_continuity_engine.graph:Graph.history",
        ),
        files=("causal_continuity_engine/graph.py",), tests=("tests/test_store_graph.py",
                                        "tests/test_regressions.py")),
    Capability(
        requirement="CCG-006", layer="Core", summary="Rebuild projections from the event log",
        status="implemented",
        honest_limit="Covers EVENT-DERIVED state. Runtime records (proofs, imported "
                     "sessions, manual checkpoints) are provenanced by signature and "
                     "audit log, not by replay — see the ADR-011 note. "
                     "The reverse comparator covers only rows with entirely event-only, "
                     "fully retained and replayable provenance; runtime and hybrid rows "
                     "remain outside that absence claim (ADR-091). "
                     "REBUILDABILITY IS BOUNDED BY THE RETENTION WINDOW: once "
                     "SEC-006 clears a payload the projection cannot be rebuilt "
                     "from the log, and `cce-engine rebuild` reports UNDECIDABLE (exit "
                     "3) rather than MATCHES or DIVERGES (ADR-063).",
        symbols=("causal_continuity_engine.engine:Engine.rebuild_projection",
                 "causal_continuity_engine.engine:Engine.projection_fingerprint",
                 "causal_continuity_engine.engine:Engine.replay_completeness",
                 "causal_continuity_engine.engine:Engine.replay_agrees_where_replayable"),
        files=("causal_continuity_engine/engine.py",), tests=("tests/test_engine_e2e.py",
                                         "tests/test_regressions_round7.py",
                                         "tests/test_regressions_round14_state_integrity.py")),
    Capability(
        requirement="CCG-008", layer="Core", summary="Bounded graph traversal",
        status="implemented",
        honest_limit="Budgets count distinct nodes (ADR-023). Bounds are per query; "
                     "there is no global cost budget across a request.",
        symbols=(
            "causal_continuity_engine.graph:Graph.dependents",
            "causal_continuity_engine.graph:TraversalBudgetExceeded",
        ),
        files=("causal_continuity_engine/graph.py",),
        tests=("tests/test_regressions_round3.py",)),
    Capability(
        requirement="TM-005", layer="Core", summary="Distil to L3 only with provenance",
        status="implemented",
        honest_limit="Provenance must RESOLVE and not be self-referential (ADR-022). "
                     "That a source exists is checked; that it supports the claim is not.",
        symbols=(
            "causal_continuity_engine.memory:Memory.promote",
            "causal_continuity_engine.memory:Memory._has_real_provenance",
        ),
        files=("causal_continuity_engine/memory.py",),
        tests=("tests/test_regressions_round3.py",)),
    Capability(
        requirement="AD-006", layer="Core", summary="Untrusted text cannot become control state",
        status="implemented",
        honest_limit="Injection screening is pattern-based and will miss novel phrasing. "
                     "The structural defences (authority typing, quarantine barred from "
                     "every tier and vacating any tier it already held) do not depend "
                     "on the patterns catching anything. The packet strip withholds "
                     "live nodes whose text matches quarantined content, which an "
                     "outsider can trigger by quoting them; those suppressions are "
                     "named and audited rather than prevented (ADR-061, ADR-062).",
        symbols=("causal_continuity_engine.github:text_authority",
                 "causal_continuity_engine.extraction:DeterministicExtractor.extract",
                 "causal_continuity_engine.resume:ResumeComposer._strip_quarantined",
                 "causal_continuity_engine.memory:Memory.demote_from_any_tier"),
        files=("causal_continuity_engine/extraction.py",
               "causal_continuity_engine/github.py",
               "causal_continuity_engine/resume.py"),
        tests=("tests/test_regressions.py", "tests/test_regressions_round3.py",
               "tests/test_regressions_round7.py")),
    Capability(
        requirement="CI-002", layer="Core", summary="Bounded blast-radius propagation",
        status="implemented",
        honest_limit="Edge strengths are configured constants, not learned or calibrated "
                     "against outcomes.",
        symbols=("causal_continuity_engine.invalidation:InvalidationEngine.fire",),
        files=("causal_continuity_engine/invalidation.py",),
        tests=("tests/test_invalidation_resume.py",)),
    Capability(
        requirement="CI-005", layer="Core", summary="Human gate for low-confidence broad impact",
        status="implemented",
        honest_limit="A gated invalidation applies NO state change, so rejecting it "
                     "strands nothing (ADR-030). Completion treats unresolved open or "
                     "pending invalidations as control state for touched nodes, and "
                     "critical unresolved invalidations as project-wide (ADR-089). "
                     "The affected set still depends on typed graph coverage and "
                     "classification.",
        symbols=("causal_continuity_engine.invalidation:InvalidationEngine.confirm",),
        files=("causal_continuity_engine/invalidation.py",),
        tests=("tests/test_regressions_round3.py",
               "tests/test_regressions_round14_state_integrity.py")),
    Capability(
        requirement="MIG-002", layer="Core", summary="Token budget never drops L0",
        status="implemented",
        honest_limit="Token counts are estimated at 4 chars/token to stay model-neutral; "
                     "a specific tokenizer will differ. Capsule currency commits the "
                     "complete semantic control basis before trimming, so budget "
                     "omissions do not create drift; this does not prove model-semantic "
                     "equivalence (ADR-094).",
        symbols=("causal_continuity_engine.resume:ResumeComposer.compose",),
        files=("causal_continuity_engine/resume.py",),
        tests=("tests/test_invalidation_resume.py",
               "tests/test_regressions_round14_state_integrity.py")),
    Capability(
        requirement="PA-005", layer="Trust", summary="Absence of success is never success",
        status="implemented",
        honest_limit="Worst-result-wins across duplicate reports (ADR-015).",
        symbols=("causal_continuity_engine.proof:ProofEnvelope.finalize",
                 "causal_continuity_engine.proof:_worst"),
        files=("causal_continuity_engine/proof.py",), tests=("tests/test_trust.py",
                                        "tests/test_regressions_round2.py")),
    Capability(
        requirement="PA-004", layer="Trust", summary="Proof bound to its subject",
        status="implemented",
        honest_limit="Completion requires a scoped, subject-bound, single-use proof "
                     "(ADR-018). Binding is checked against SIGNED fields only.",
        symbols=("causal_continuity_engine.engine:Engine.complete_task",
                 "causal_continuity_engine.engine:_proof_covers"),
        files=("causal_continuity_engine/engine.py",),
        tests=("tests/test_regressions_round2.py",)),
    Capability(
        requirement="EV-004", layer="Trust", summary="Requirement-specific verifier policy",
        status="implemented",
        honest_limit="Policy-mandated verifiers are non-substitutable ONLY when pinned "
                     "with a command (ADR-024). A bare-name entry is satisfiable by a "
                     "command the claimant chooses; the grade caps at D and the proof "
                     "records it under evidence_context.unpinned_required.",
        symbols=("causal_continuity_engine.policy:PolicyEngine.required_verifier_defs",
                 "causal_continuity_engine.verifiers:VerifierSpec.from_policy"),
        files=("causal_continuity_engine/policy.py", "causal_continuity_engine/verifiers.py"),
        tests=("tests/test_regressions_round4.py",)),
    Capability(
        requirement="EV-005", layer="Trust",
        summary="Reject evidence that no longer describes current deliverables",
        status="implemented",
        honest_limit="Covers declared artifacts and signed continuity inputs. Every "
                     "declared artifact route and nested descendant must remain physical "
                     "under the work tree; symlink/reparse routing fails closed. These "
                     "standard-library checks are not kernel isolation and cannot "
                     "eliminate privileged concurrent filesystem mutation (ADR-096). "
                     "An undeclared artifact has no staleness surface.",
        symbols=("causal_continuity_engine.engine:Engine.proof_currency",
                 "causal_continuity_engine.engine:Engine._artifact_digests",
                 "causal_continuity_engine.engine:Engine.complete_task"),
        files=("causal_continuity_engine/engine.py",),
        tests=("tests/test_regressions_round6.py",
               "tests/test_regressions_round14_state_integrity.py")),
    Capability(
        requirement="EV-006", layer="Trust", summary="Verifier sandboxing and limits",
        status="partial",
        honest_limit="Timeouts, output caps, a scrubbed environment with a named threat "
                     "per entry, and a guard on commands that delegate to another "
                     "program. NOT kernel isolation, and NOT a defence against in-process "
                     "forgery: a test must import the code under test, so the subject can "
                     "rewrite the runner's report. Use value-oracle checks and mutation "
                     "probes for that (ADR-025), and containers for SEC-008.",
        symbols=("causal_continuity_engine.verifiers:VerifierRunner._build_env",
                 "causal_continuity_engine.verifiers:check_command_safety"),
        files=("causal_continuity_engine/verifiers.py",),
        tests=("tests/test_regressions_round4.py",)),
    Capability(
        requirement="EV-007", layer="Trust", summary="Expose unverified surface area",
        status="implemented",
        honest_limit="The mutation probe is a mechanical LOWER BOUND: it proves a check "
                     "binds to a deliverable's existence and content, never that it "
                     "checks the right property (ADR-027). Per-file line coverage is "
                     "still not computed. Only a FAILED check counts as a detection; "
                     "a check that crashed establishes nothing and leaves binding "
                     "undetermined rather than proven (ADR-066).",
        symbols=("causal_continuity_engine.evidence:run_mutation_probe",
                 "causal_continuity_engine.evidence:grade_evidence",
                 "causal_continuity_engine.evidence:MutationReport.bound",
                 "causal_continuity_engine.engine:Engine.probe_evidence"),
        files=("causal_continuity_engine/evidence.py",), tests=("tests/test_regressions_round4.py",
                                           "tests/test_regressions_round7.py")),
    Capability(
        requirement="AUT-005", layer="Trust", summary="Automatic autonomy downgrade",
        status="implemented",
        honest_limit="Fires on failed proof, failed migration challenge and critical "
                     "invalidation. Clearing is an explicit human act.",
        symbols=("causal_continuity_engine.policy:PolicyEngine.downgrade",),
        files=("causal_continuity_engine/policy.py",), tests=("tests/test_regressions.py",)),
    Capability(
        requirement="SEC-003", layer="Platform", summary="Capture modes",
        status="implemented",
        honest_limit="Redaction is applied before persistence and extraction reads the "
                     "persisted form (ADR-016), so nothing dropped reaches the graph. "
                     "Secret patterns are a denylist and will miss novel formats.",
        symbols=("causal_continuity_engine.redaction:apply_capture_mode",
                 "causal_continuity_engine.redaction:redact_text"),
        files=("causal_continuity_engine/redaction.py",), tests=("tests/test_github_redaction.py",
                                            "tests/test_regressions_round3.py")),
    Capability(
        requirement="SEC-007", layer="Platform", summary="Append-only audit log",
        status="implemented",
        honest_limit="Triggers refuse mutation, a hash chain detects rewrites even if the "
                     "triggers are dropped, and a closed typed anchor can detect tail "
                     "truncation and optionally bind tenant/project scope. Malformed "
                     "anchors fail cleanly, but an unbound anchor proves no scope and ANY "
                     "anchor matters externally ONLY if published somewhere the operator "
                     "does not control. CCE ships no publication channel (ADR-028, "
                     "ADR-095).",
        symbols=("causal_continuity_engine.store:Store.verify_chain",
                 "causal_continuity_engine.store:Store.export_anchor",
                 "causal_continuity_engine.store:Store.verify_against_anchor"),
        files=("causal_continuity_engine/store.py",), tests=("tests/test_regressions_round4.py",
                                           "tests/test_regressions_round14_state_integrity.py")),
    Capability(
        requirement="SEC-002", layer="Platform", summary="Tenant isolation",
        status="partial",
        honest_limit="Every row is tenant-scoped and queries are project-scoped, but "
                     "enforcement is application-level. Database row-level security "
                     "needs the PostgreSQL deployment (ADR-011).",
        symbols=("causal_continuity_engine.store:Store.append_event",),
        files=("causal_continuity_engine/store.py",), tests=("tests/test_store_graph.py",)),
    Capability(
        requirement="SEC-008", layer="Platform", summary="Deny-by-default tool sandboxing",
        status="partial",
        honest_limit="The runner records the network policy it was ASKED for; it does not "
                     "enforce it. Kernel-level isolation is a deployment concern.",
        symbols=("causal_continuity_engine.verifiers:VerifierRunner.run",),
        files=("causal_continuity_engine/verifiers.py",), tests=("tests/test_trust.py",)),
    Capability(
        requirement="PA-003", layer="Trust",
        summary="Third-party-verifiable proof envelopes",
        status="implemented",
        honest_limit="SPEC.md is normative and verifiers/verify_proof.py "
                     "implements it importing nothing from "
                     "causal_continuity_engine; every committed "
                     "vector pins both implementations. This shows the spec is "
                     "unambiguous enough to reimplement — it does NOT constitute "
                     "implementation independence, because both have one author. "
                     "A stranger still needs the key fingerprint out of band, and "
                     "CCE ships no channel for that (ADR-031, ADR-057). "
                     "hmac-sha256 IS NOT THIRD-PARTY VERIFIABLE AT ALL: without "
                     "the secret the verifier returns UNVERIFIED, never VALID, "
                     "because an untouched envelope and a resealed forgery are "
                     "indistinguishable to a keyless party. Only lamport-sha256/1 "
                     "plus an out-of-band fingerprint reaches VALID for a "
                     "stranger (ADR-057).",
        symbols=("verifiers.verify_proof:verify",
                 "verifiers.verify_proof:derive_fingerprint"),
        files=("SPEC.md", "verifiers/verify_proof.py", "vectors/generate.py"),
        tests=("tests/test_conformance.py", "tests/test_regressions_round7.py")),
    Capability(
        requirement="PLT-005", layer="Platform", summary="Web dashboard",
        status="out-of-scope",
        honest_limit="Not built. The HTTP API serves the same data."),
    Capability(
        requirement="NFR-001", layer="Platform", summary="Webhook SLOs",
        status="out-of-scope",
        honest_limit="Latency targets need deployed infrastructure and representative "
                     "traffic; local execution cannot evidence a deployment SLO."),
)


@dataclass
class CapabilityResult:
    capability: Capability
    ok: bool
    problems: list[str] = field(default_factory=list)


def verify(capabilities=CAPABILITIES) -> list[CapabilityResult]:
    """Resolve every declared symbol, file and test. Claims must be real."""
    results = []
    for cap in capabilities:
        problems: list[str] = []
        for symbol in cap.symbols:
            try:
                _resolve(symbol)
            except (ImportError, AttributeError, ValueError) as exc:
                problems.append(f"symbol {symbol!r} does not resolve: {exc}")
        for rel in cap.files + cap.tests:
            if not _evidence_exists(rel):
                problems.append(f"missing file {rel!r}")
        if cap.status in ("implemented", "partial") and not cap.honest_limit:
            problems.append("no honest_limit recorded")
        results.append(CapabilityResult(cap, not problems, problems))
    return results


def render_markdown(capabilities=CAPABILITIES) -> str:
    """Generate the coverage table FROM the declarations."""
    lines = [
        "# Requirement coverage — generated, do not edit by hand",
        "",
        (
            "Generated by `python -m causal_continuity_engine.capabilities --write`. Every row is "
            "checked"
        ),
        "by `TestCapabilitiesAudit` in `tests/test_regressions_round4.py`: the",
        "symbols must import and the files and tests must exist, so a claim",
        "cannot outlive the code behind it.",
        "",
        "The **honest limit** column is the point of this table. A status of",
        "`implemented` means the mechanism exists and is tested — never that",
        "the requirement is solved in full.",
        "",
        "| Requirement | Layer | Capability | Status | Honest limit |",
        "|---|---|---|---|---|",
    ]
    for cap in capabilities:
        limit = cap.honest_limit.replace("\n", " ").replace("|", "\\|")
        lines.append(
            f"| {cap.requirement} | {cap.layer} | {cap.summary} | "
            f"`{cap.status}` | {limit} |")
    lines += [
        "",
        "## What this table is not",
        "",
        "It records that claimed code exists and has tests. It cannot record",
        "that the code is correct; the suite and ContinuityBench address that,",
        "and ContinuityBench is self-scored on deterministic fixtures.",
        "",
        "The public meaning of every requirement ID is defined in",
        "[REQUIREMENTS.md](REQUIREMENTS.md). Narrative implementation status and evidence,",
        "including IDs with no capability declaration here, remain in",
        "[REQUIREMENTS_COVERAGE.md](REQUIREMENTS_COVERAGE.md).",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    import sys as _sys
    argv = _sys.argv[1:] if argv is None else argv
    if "--write" in argv:
        target = ROOT / "docs" / "CAPABILITIES.md"
        # Generated documentation is a build input.  Platform-default text
        # encoding made the Windows gate emit CP1252 and CRLF while Linux
        # committed UTF-8 and LF, so a clean checkout failed its own audit.
        target.write_text(render_markdown(), encoding="utf-8", newline="\n")
        print(f"wrote {target.relative_to(ROOT)}")
    results = verify()
    failed = [r for r in results if not r.ok]
    for r in failed:
        print(f"FAIL {r.capability.requirement}: " + "; ".join(r.problems))
    counts: dict[str, int] = {}
    for r in results:
        counts[r.capability.status] = counts.get(r.capability.status, 0) + 1
    print(f"{len(results)} capability claims checked: "
          + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    if failed:
        print(f"{len(failed)} claim(s) do not resolve")
        return 1
    print("every claim resolves to real symbols, files and tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
