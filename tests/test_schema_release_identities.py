"""Schema identities are reviewed release operands, never payload self-claims.

All fetches below read disposable or checked-out local bytes. These checks do
not establish that a public tag or network-hosted schema currently exists.
"""

import json
from pathlib import Path

import pytest

from tests.test_regressions_round10_release import _load_release_script

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://raw.githubusercontent.com/thequantumfalcon/causal-continuity-engine"
RELEASES = {
    "cce.anchor.v1.json": "v0.1.0",
    "cce.capsule.v1.json": "v0.1.0",
    "cce.continuity-receipt.v1.json": "v0.1.0",
    "cce.event.v1.json": "v0.1.0",
    "cce.proof-predicate.v1.json": "v0.1.0",
    "cce.proof.v1.json": "v0.1.0",
    "cce.recovery.v1.json": "v0.1.0",
    "cce.resume.v1.json": "v0.1.0",
    "cce.capsule.v2.json": "v0.2.0",
    "cce.continuity-receipt.v2.json": "v0.2.0",
    "cce.proof-predicate.v2.json": "v0.2.0",
    "cce.proof.v2.json": "v0.2.0",
    "cce.resume.v2.json": "v0.2.0",
}
URLS = {name: f"{ORIGIN}/{release}/schemas/{name}" for name, release in RELEASES.items()}


def _fixture(root, name, data):
    package = root / "causal_continuity_engine"
    package.mkdir()
    (package / "__init__.py").write_text(
        "SCHEMA_VERSIONS = " + repr({"fixture": name.removesuffix(".json")}) + "\n",
        encoding="utf-8")
    schemas = root / "schemas"
    schemas.mkdir()
    (schemas / name).write_bytes(data)


def test_release_identity_map_matches_literal_reviewed_inventory():
    verifier = _load_release_script("verify_public_schemas")
    assert {path.name for path in (ROOT / "schemas").glob("*.json")} == set(RELEASES)
    assert verifier._schema_public_urls(ROOT) == URLS


def test_every_checked_out_schema_claims_its_independent_expected_identity():
    for name, expected in URLS.items():
        assert json.loads((ROOT / "schemas" / name).read_bytes())["$id"] == expected


@pytest.mark.parametrize("package_tag", ["v0.2.0", "v9.9.9"])
def test_all_actual_schema_bytes_verify_at_their_own_immutable_releases(package_tag):
    verifier = _load_release_script("verify_public_schemas")
    served = {url: (ROOT / "schemas" / name).read_bytes() for name, url in URLS.items()}
    requested = []

    def fetch(url):
        requested.append(url)
        return served[url]

    verifier.verify(ROOT, package_tag, fetch=fetch)
    assert requested == [URLS[name] for name in sorted(URLS)]


def test_unknown_registered_schema_cannot_invent_an_immutable_release(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    name = "cce.future-fixture.v1.json"
    _fixture(tmp_path, name, json.dumps({"$id": f"{ORIGIN}/v0.1.0/schemas/{name}"}).encode())
    with pytest.raises(SystemExit, match="unreviewed|unknown|release identity"):
        verifier._schema_public_urls(tmp_path)


@pytest.mark.parametrize("name,claimed_release", [
    ("cce.proof.v2.json", "v0.1.0"),
    ("cce.resume.v2.json", "v0.1.0"),
    ("cce.capsule.v2.json", "v0.1.0"),
    ("cce.continuity-receipt.v2.json", "v0.1.0"),
    ("cce.proof-predicate.v2.json", "v0.1.0"),
    ("cce.event.v1.json", "v0.2.0"),
])
def test_payload_id_cannot_choose_its_own_expected_release(tmp_path, name, claimed_release):
    verifier = _load_release_script("verify_public_schemas")
    data = json.dumps({"$id": f"{ORIGIN}/{claimed_release}/schemas/{name}"}).encode()
    _fixture(tmp_path, name, data)
    requested = []
    with pytest.raises(SystemExit, match=r"has \$id"):
        verifier.verify(tmp_path, "v9.9.9", fetch=lambda url: requested.append(url) or data)
    assert requested == []


@pytest.mark.parametrize("data", [
    b'{"$id":',
    b'{"$id":"first","$id":"second"}',
    b'{"$id":NaN}',
])
def test_malformed_or_duplicate_local_id_refuses_before_fetch(tmp_path, data):
    verifier = _load_release_script("verify_public_schemas")
    _fixture(tmp_path, "cce.event.v1.json", data)
    requested = []
    with pytest.raises(SystemExit, match="strict UTF-8 JSON"):
        verifier.verify(tmp_path, "v9.9.9", fetch=lambda url: requested.append(url) or data)
    assert requested == []


@pytest.mark.parametrize("failure", ["duplicate_id", "wrong_release", "changed_bytes"])
def test_served_schema_identity_and_exact_bytes_remain_required(tmp_path, failure):
    verifier = _load_release_script("verify_public_schemas")
    name = "cce.resume.v2.json"
    data = json.dumps({"$id": URLS[name], "type": "object"}).encode()
    _fixture(tmp_path, name, data)
    if failure == "duplicate_id":
        served = b'{"$id":"first","$id":"second"}'
        reason = "strict UTF-8 JSON"
    elif failure == "wrong_release":
        served = json.dumps({"$id": URLS[name].replace("/v0.2.0/", "/v0.1.0/")}).encode()
        reason = r"served schema has the wrong \$id"
    else:
        served = data + b"\n"
        reason = "bytes differ"
    with pytest.raises(SystemExit, match=reason):
        verifier.verify(tmp_path, "v9.9.9", fetch=lambda _url: served)


def test_duplicate_registry_values_cannot_alias_one_reviewed_schema(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    _fixture(tmp_path, "cce.event.v1.json", b"{}")
    (tmp_path / "causal_continuity_engine" / "__init__.py").write_text(
        "SCHEMA_VERSIONS = {'first': 'cce.event.v1', 'second': 'cce.event.v1'}\n",
        encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicated"):
        verifier._schema_public_urls(tmp_path)
