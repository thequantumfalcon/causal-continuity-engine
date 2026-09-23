"""Public quickstart text agrees with the exact local recipe exercised by the CLI test."""

import re
from pathlib import Path

import pytest

from causal_continuity_engine import SCHEMA_VERSIONS

ROOT = Path(__file__).resolve().parents[1]

# Kept in the installed audit test payload: README itself is package metadata,
# not an installed audit file. The source test below requires exact code equality.
REVIEW_REQUEST_SCRIPT = '''import json
from pathlib import Path

from causal_continuity_engine.engine import Engine

root = Path.cwd()
meta = json.loads((root / ".cce" / "meta.json").read_text(encoding="utf-8"))
engine = Engine(root / ".cce" / "cce.db", tenant_id=meta["tenant_id"], workdir=root)
try:
    def prepare(kind, text):
        matches = [node for node in engine.graph.current(
            meta["project_id"], "claim", tenant_id=meta["tenant_id"])
            if node["data"].get("proposed_kind") == kind
            and node["data"].get("statement") == text]
        if len(matches) != 1:
            raise ValueError("expected exactly one matching retained proposal")
        proposal = engine.authority_proposal(meta["project_id"], matches[0]["node_id"])
        request = {
            "operation": "confirm", "request_id": "quickstart-" + kind,
            "tenant_id": meta["tenant_id"], "project_id": meta["project_id"],
            **proposal, "authority_scope": {"kind": "global"},
        }
        (root / ("review-" + kind + ".json")).write_text(
            json.dumps(request, indent=2) + "\\n", encoding="utf-8")

    prepare("requirement", "Exporter must stream rows instead of buffering")
    prepare("constraint", "The exporter must not hold the whole result set in memory")
    prepare("assumption", "the upstream feed is ordered by timestamp")
finally:
    engine.close()
'''

PACKET_EXCERPT = '''Scope: {"kind": "project"} | complete: True
Response: cli-markdown | max bytes: 131072

## Mandatory control
...
## Authority
...
### Active requirements
- Exporter must stream rows instead of buffering
...
## Trust
- autonomy level: 0
- required verifiers: none
- verification gaps: policy:proof-required-without-required-verifiers
...
## Transport and cryptographic metadata
...
- schema: cce.resume.v2
- packet digest present: True
- signature present: True
'''


def test_readme_review_program_is_the_executed_quickstart_program():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"<!-- quickstart-review-requests -->\n\n```python\n(.*?)\n```", readme, re.DOTALL)
    assert match is not None, "README omits the reviewed local proposal preparation program"
    assert match.group(1) + "\n" == REVIEW_REQUEST_SCRIPT


def test_readme_packet_excerpt_is_checked_against_real_cli_output():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"<!-- quickstart-packet-excerpt -->\n\n```markdown\n(.*?)\n```", readme, re.DOTALL)
    assert match is not None, "README omits the measured v2 packet excerpt"
    assert match.group(1) + "\n" == PACKET_EXCERPT


@pytest.mark.parametrize("schema, pattern", [
    ("resume_packet", r"- schema: (cce\.resume\.v\d+)"),
    ("proof", r"it defines the `(cce\.proof\.v\d+)` envelope"),
])
def test_readme_current_wire_identities_match_runtime_inventory(schema, pattern):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(pattern, readme)
    assert match is not None, "README omits the current wire identity"
    assert match.group(1) == SCHEMA_VERSIONS[schema], "README has a stale current wire identity"


def test_release_guide_current_receipt_identity_matches_runtime_inventory():
    guide = (ROOT / "docs/RELEASE.md").read_text(encoding="utf-8")
    match = re.search(r"engine now emits signed `(cce\.continuity-receipt\.v\d+)`", guide)
    assert match is not None, "release guide omits the current receipt identity"
    assert match.group(1) == SCHEMA_VERSIONS["continuity_receipt"]
