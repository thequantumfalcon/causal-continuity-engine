"""GitHub webhook verification/normalization and redaction/capture modes."""

import hashlib
import hmac
import json
import time

import pytest

from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.github import (
    WebhookError,
    continuity_conclusion,
    normalize,
    text_authority,
    verify_signature,
)
from causal_continuity_engine.redaction import (
    _SECRET_PATTERNS,
    _capture_payload_is_current,
    apply_capture_mode,
    redact_text,
    scan_secrets,
)


class TestSignature:
    SECRET = b"webhook-secret"

    def _sig(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self.SECRET, body, hashlib.sha256).hexdigest()

    def test_valid_signature(self):
        body = json.dumps({"x": 1}).encode()
        assert verify_signature(self.SECRET, body, self._sig(body))

    def test_forged_signature_rejected(self):
        body = json.dumps({"x": 1}).encode()
        assert not verify_signature(self.SECRET, body, "sha256=" + "0" * 64)

    def test_missing_or_malformed_rejected(self):
        assert not verify_signature(self.SECRET, b"x", None)
        assert not verify_signature(self.SECRET, b"x", "sha1=abc")

    def test_body_tamper_rejected(self):
        body = json.dumps({"x": 1}).encode()
        sig = self._sig(body)
        assert not verify_signature(self.SECRET, b'{"x": 2}', sig)


class TestNormalize:
    def test_unsubscribed_event_rejected(self):
        with pytest.raises(WebhookError):
            normalize("gollum", "d1", {})

    def test_push_flags_and_authority(self):
        env = normalize("push", "d1", {
            "ref": "refs/heads/main", "before": "a" * 40, "after": "b" * 40,
            "forced": True, "deleted": False, "created": False,
            "commits": [{"id": "b" * 40, "message": "fix parser",
                         "timestamp": "2026-07-29T10:00:00Z"}],
            "head_commit": {"timestamp": "2026-07-29T10:00:00Z"},
            "repository": {"id": 1, "full_name": "o/r"},
        })
        assert env["authority"] == "repository_authoritative"
        assert env["flags"]["forced"] is True
        assert env["idempotency_key"] == "github:d1"
        # commit MESSAGES are author-written free text (GHI/AD-006)
        assert env["text_blocks"][0]["authority"] == "untrusted_content"

    def _issue_env(self, association, delivery="d2"):
        return normalize("issues", delivery, {
            "action": "opened",
            "issue": {"number": 5, "title": "T", "body": "B", "state": "open",
                      "labels": [], "author_association": association,
                      "created_at": "2026-07-29T10:00:00Z"},
            "repository": {"id": 1, "full_name": "o/r"},
        })

    def test_maintainer_issue_text_is_human_intent(self):
        for association in ("OWNER", "MEMBER", "COLLABORATOR"):
            env = self._issue_env(association)
            assert env["authority"] == "human_intent"
            assert all(b["authority"] == "human_intent" for b in env["text_blocks"])

    def test_outsider_issue_text_is_untrusted(self):
        for association in ("NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR",
                            "MANNEQUIN", None):
            env = self._issue_env(association)
            assert env["authority"] == "untrusted_content"
            assert all(b["authority"] == "untrusted_content"
                       for b in env["text_blocks"])

    def test_text_authority_helper(self):
        assert text_authority("OWNER") == "human_intent"
        assert text_authority("owner") == "human_intent"
        assert text_authority("NONE") == "untrusted_content"
        assert text_authority(None) == "untrusted_content"

    def test_check_run_verifier_authoritative(self):
        env = normalize("check_run", "d3", {
            "action": "completed",
            "check_run": {"id": 9, "name": "unit-tests", "status": "completed",
                          "conclusion": "failure", "head_sha": "c" * 40,
                          "completed_at": "2026-07-29T11:00:00Z",
                          "app": {"id": 101, "slug": "gh-actions"}},
            "installation": {"id": 501},
            "repository": {"id": 1, "full_name": "o/r"},
        })
        assert env["authority"] == "verifier_authoritative"
        assert env["flags"]["conclusion"] == "failure"
        assert env["flags"]["app_id"] == 101
        assert env["flags"]["installation_id"] == 501

    def test_comment_command_detected(self):
        env = normalize("issue_comment", "d4", {
            "action": "created",
            "issue": {"number": 7},
            "comment": {"id": 1, "body": "/cce resume",
                        "author_association": "OWNER",
                        "created_at": "2026-07-29T10:00:00Z"},
            "repository": {"id": 1, "full_name": "o/r"},
        })
        assert env["flags"]["command"] == "/cce resume"
        assert env["flags"]["author_association"] == "OWNER"

    def test_release_body_untrusted(self):
        env = normalize("release", "d5", {
            "action": "published",
            "release": {"id": 1, "tag_name": "v1", "body": "notes",
                        "published_at": "2026-07-29T10:00:00Z"},
            "repository": {"id": 1, "full_name": "o/r"},
        })
        assert env["text_blocks"][0]["authority"] == "untrusted_content"


class TestCheckConclusion:
    def test_matrix(self):
        assert continuity_conclusion(critical_invalidation=False, proof_ok=True,
                                     packet_current=True, authority_conflict=False,
                                     approval_needed=False,
                                     trust_unavailable=False) == "success"
        assert continuity_conclusion(critical_invalidation=True, proof_ok=True,
                                     packet_current=True, authority_conflict=False,
                                     approval_needed=False,
                                     trust_unavailable=False) == "action_required"
        assert continuity_conclusion(critical_invalidation=False, proof_ok=False,
                                     packet_current=True, authority_conflict=False,
                                     approval_needed=False,
                                     trust_unavailable=False) == "failure"
        # Trust unavailable NEVER converts to success (GHI-004).
        assert continuity_conclusion(critical_invalidation=False, proof_ok=True,
                                     packet_current=True, authority_conflict=False,
                                     approval_needed=False,
                                     trust_unavailable=True) == "cancelled"
        assert continuity_conclusion(critical_invalidation=False, proof_ok=True,
                                     packet_current=False, authority_conflict=False,
                                     approval_needed=False,
                                     trust_unavailable=False) == "neutral"


class TestRedaction:
    def test_scan_and_redact_known_secrets(self):
        text = ("token ghp_ABCDEFghijklmnopqrstuvwx123456 and key "
                "AKIAIOSFODNN7EXAMPLE plus password: hunter2secret")
        kinds = {f["kind"] for f in scan_secrets(text)}
        assert {"github_token", "aws_access_key", "generic_assignment"} <= kinds
        clean, found = redact_text(text)
        assert "ghp_" not in clean and "AKIA" not in clean
        assert "hunter2secret" not in clean
        assert "[REDACTED:github_token]" in clean

    def test_private_key_block(self):
        text = ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n"
                "-----END RSA PRIVATE KEY-----")
        clean, found = redact_text(text)
        assert "MIIabc" not in clean and "private_key_block" in found

    def test_truncated_private_key_redaction_stops_before_syntactically_distinct_tail(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = f"prefix\n{begin}\nMIIabcdef0123456789+/=\noperator note must survive!\nsuffix"
        clean, found = redact_text(text)
        assert "private_key_block" in found
        assert begin not in clean
        assert "MIIabcdef0123456789+/=" not in clean
        assert "operator note must survive!\nsuffix" in clean

        findings = [item for item in scan_secrets(text)
                    if item["kind"] == "private_key_block"]
        assert len(findings) == 1
        assert text[findings[0]["end"]:] == "\noperator note must survive!\nsuffix"

    def test_truncated_private_key_redacts_noncanonical_odd_wrap(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        body_line = "MIIabc"
        assert len(body_line) % 4 != 0
        clean, found = redact_text(f"{begin}\n{body_line}")
        assert clean == "[REDACTED:private_key_block]"
        assert found == ["private_key_block"]

    @pytest.mark.parametrize("separator", [" ", "\t", "\v", "\f", "\r"])
    def test_truncated_private_key_redacts_internal_ascii_whitespace(self, separator):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        body_line = f"MIIE{separator}AABB"
        text = f"{begin}\n{body_line}\nQUJDRA==\ncontrol boundary!"
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert body_line not in clean
        assert "QUJDRA==" not in clean
        assert clean == "[REDACTED:private_key_block]\ncontrol boundary!"

        findings = [item for item in scan_secrets(text)
                    if item["kind"] == "private_key_block"]
        assert len(findings) == 1
        assert text[findings[0]["end"]:] == "\ncontrol boundary!"

    @pytest.mark.parametrize("label", [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ])
    def test_truncated_private_key_labels_redact_spaced_body(self, label):
        begin = "-" * 5 + f"BEGIN {label}" + "-" * 5
        clean, found = redact_text(
            f"{begin}\nMIIESPACEBODY AABBSPACEBODY\ncontrol boundary!")
        assert found == ["private_key_block"]
        assert clean == "[REDACTED:private_key_block]\ncontrol boundary!"

    def test_truncated_private_key_redacts_legacy_headers_before_spaced_body(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = (f"{begin}\nProc-Type: 4,ENCRYPTED\n"
                "DEK-Info: AES-256-CBC,0123456789ABCDEF\n"
                "MIIE AABB\nQUJDRA==\ncontrol boundary!")
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert "Proc-Type" not in clean
        assert "MIIE AABB" not in clean
        assert "QUJDRA==" not in clean
        assert clean == "[REDACTED:private_key_block]\ncontrol boundary!"

    @pytest.mark.parametrize("line_ending", ["\r", "\r\n"])
    def test_truncated_private_key_accepts_carriage_return_line_endings(self, line_ending):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = line_ending.join(
            (begin, "MIIE AABB", "QUJDRA==", "control boundary!"))
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert clean == f"[REDACTED:private_key_block]{line_ending}control boundary!"

    def test_complete_private_key_accepts_cr_only_begin_body_end_lines(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        end = "-" * 5 + "END RSA PRIVATE KEY" + "-" * 5
        text = "\r".join((begin, "MIIE AABB", end, "control tail"))
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert clean == "[REDACTED:private_key_block]\rcontrol tail"

    def test_truncated_private_key_leaves_trailing_blank_only_lines_outside_span(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = f"{begin}\nMIIE AABB\n \t\v\f\n"
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert clean == "[REDACTED:private_key_block]\n \t\v\f\n"

    def test_truncated_private_key_fails_closed_over_spaced_control_tail(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = f"prefix\n{begin}\nMIIE AABB\noperator note must survive\nsuffix"
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert clean == "prefix\n[REDACTED:private_key_block]"

    def test_truncated_private_key_whitespace_scanning_scales_linearly(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        body_line = "MIIE AABB\tCCDD\vEEFF\fGGHH\n"

        def elapsed(count):
            text = f"{begin}\n{body_line * count}control boundary!"
            samples = []
            for _ in range(3):
                started = time.perf_counter()
                findings = [item for item in scan_secrets(text)
                            if item["kind"] == "private_key_block"]
                samples.append(time.perf_counter() - started)
                assert len(findings) == 1
                assert text[findings[0]["end"]:] == "\ncontrol boundary!"
            return min(samples)

        small = elapsed(2_000)
        large = elapsed(8_000)
        assert large < max(small * 10, 0.02), (small, large)

    def test_truncated_private_key_fails_closed_over_ambiguous_control_tail(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        text = f"{begin}\nQUJDRA==\n\nREQUIREMENT\nTODO"
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert clean == "[REDACTED:private_key_block]"

        findings = [item for item in scan_secrets(text)
                    if item["kind"] == "private_key_block"]
        assert len(findings) == 1
        assert findings[0]["end"] == len(text)

    def test_complete_private_key_block_fails_closed_over_non_base64_lines(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
        end = "-" * 5 + "END RSA PRIVATE KEY" + "-" * 5
        text = f"{begin}\nopaque key material with spaces\n{end}\nunrelated tail"
        clean, found = redact_text(text)
        assert found == ["private_key_block"]
        assert "opaque key material" not in clean
        assert "unrelated tail" in clean

    def test_unterminated_private_key_markers_scale_without_quadratic_rescan(self):
        begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5

        def elapsed(count):
            text = (begin + "\n") * count
            samples = []
            for _ in range(3):
                started = time.perf_counter()
                scan_secrets(text)
                samples.append(time.perf_counter() - started)
            return min(samples)

        small = elapsed(400)
        large = elapsed(1600)
        assert large < max(small * 10, 0.01), (small, large)

        clean, found = redact_text((begin + "\n") * 40)
        assert found.count("private_key_block") == 40
        assert begin not in clean

    def test_private_key_replacement_scales_with_input_size(self):
        block = ("-----BEGIN RSA PRIVATE KEY-----\nQUJD\n"
                 "-----END RSA PRIVATE KEY-----\n")

        def elapsed(size):
            count = size // len(block)
            text = block * count
            samples = []
            for _ in range(2):
                started = time.perf_counter()
                clean, found = redact_text(text)
                samples.append(time.perf_counter() - started)
                assert found == ["private_key_block"] * count
                assert "-----BEGIN" not in clean
            return min(samples)

        small = elapsed(512 * 1024)
        large = elapsed(2 * 1024 * 1024)
        assert large < small * 10, (small, large)

    def test_capture_mode_metadata_only_drops_content(self):
        payload = {"issue": {"number": 5, "body": "long text here",
                             "title": "some title"}}
        out, report = apply_capture_mode(payload, "metadata_only")
        assert out["issue"]["number"] == 5
        assert out["issue"]["body"].startswith("[DROPPED:body:")
        assert report["dropped_fields"] == 2

    def test_capture_mode_redacted_keeps_clean_content(self):
        payload = {"body": "we assume x. token ghp_ABCDEFghijklmnopqrstuvwx123456"}
        out, report = apply_capture_mode(payload, "redacted")
        assert "we assume x" in out["body"]
        assert "ghp_" not in out["body"]
        assert "github_token" in report["redactions"]

    def test_full_mode_still_redacts_secrets(self):
        payload = {"body": "key AKIAIOSFODNN7EXAMPLE"}
        out, _ = apply_capture_mode(payload, "full")
        assert "AKIA" not in out["body"]

    def test_metadata_validator_accepts_generated_nested_placeholders(self):
        stored, _ = apply_capture_mode(
            {"body": {
                "password": "abcdefghijklmnop",
                "items": ["x", {"secret": "y" * 40}],
            }},
            "metadata_only",
        )
        assert stored["body"]["password"] == "[DROPPED:password:16chars]"
        assert stored["body"]["items"][0] == "[DROPPED:items:1chars]"
        assert (stored["body"]["items"][1]["secret"]
                == "[DROPPED:secret:40chars]")
        assert _capture_payload_is_current(stored, "metadata_only") is True

    def test_metadata_capture_rewrites_source_text_that_looks_like_placeholder(
            self):
        source = "[DROPPED:body:4111111111111111chars]"
        stored, _ = apply_capture_mode({"body": source}, "metadata_only")
        assert stored["body"] == f"[DROPPED:body:{len(source)}chars]"
        assert stored["body"] != source
        assert _capture_payload_is_current(stored, "metadata_only") is True

    @pytest.mark.parametrize("payload", [
        {"body": {"note": "[DROPPED:secret:40chars]"}},
        {"body": {"note": "[DROPPED:note:040chars]"}},
        {"body": {"note": "[DROPPED:note:٤٠chars]"}},
        {"body": {"note": "[DROPPED:note:40chars]extra"}},
    ], ids=("wrong-key", "leading-zero", "unicode-digits", "suffix"))
    def test_metadata_validator_rejects_noncanonical_placeholders(self, payload):
        assert _capture_payload_is_current(payload, "metadata_only") is False

    def test_metadata_validator_does_not_privilege_non_content_sentinels(self):
        clean = {"metadata": "[DROPPED:metadata:40chars]"}
        sensitive = {"metadata": "[DROPPED:password:16chars]"}
        assert _capture_payload_is_current(clean, "metadata_only") is True
        assert _capture_payload_is_current(sensitive, "metadata_only") is False

    def test_unknown_mode_rejected(self):
        with pytest.raises(ValueError):
            apply_capture_mode({}, "everything")

    @pytest.mark.parametrize("mode", sorted(("metadata_only", "redacted", "full")))
    def test_secret_bearing_mapping_key_is_refused_without_echo(self, mode):
        secret = "".join(("ghp_", "KEYMATERIAL0123456789abcdefghij"))
        with pytest.raises(ValueError, match="secret-bearing object key") as caught:
            apply_capture_mode({"nested": {secret: "ordinary value"}}, mode)
        assert secret not in str(caught.value)


def test_spaced_truncated_key_never_crosses_the_ingest_boundary(tmp_path):
    project_id = "prj_pem_whitespace"
    repository_id = 2003
    database = tmp_path / "state.sqlite3"
    begin = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
    fragments = ("MIIE", "AABB", "CCDD", "QUJDRA==")
    body = (f"The exporter must retain public context.\n{begin}\n"
            "MIIE AABB\tCCDD\nQUJDRA==\ncontrol boundary!")
    payload = {
        "action": "opened",
        "issue": {
            "number": 1,
            "title": "Public title",
            "body": body,
            "state": "open",
            "labels": [],
            "author_association": "OWNER",
            "created_at": "2026-07-29T10:00:00Z",
        },
        "repository": {"id": repository_id, "full_name": "o/r"},
    }

    def assert_private_material_absent(engine, event_id):
        stored = json.dumps(
            engine.store.get_event(
                event_id, tenant_id=engine.tenant_id,
                project_id=project_id)["payload"],
            sort_keys=True,
        )
        graph = json.dumps(engine.graph.current(project_id), default=str, sort_keys=True)
        packet = json.dumps(engine.resume_packet(project_id), sort_keys=True)
        assert "[REDACTED:private_key_block]" in stored
        for fragment in fragments:
            assert fragment not in stored
            assert fragment not in graph
            assert fragment not in packet
        marker = engine.store._conn.execute(
            "SELECT processor_version, status, error FROM processed_events "
            "WHERE event_id = ?", (event_id,)).fetchone()
        assert tuple(marker) == (PROCESSOR_VERSION, "ok", None)

    engine = Engine(database, workdir=tmp_path)
    try:
        engine.create_project(
            "p", project_id=project_id, repository_id=repository_id)
        report = engine.ingest_github(project_id, "issues", "delivery-1", payload)
        event_id = report["event_id"]
        signer = engine.signer
        assert report["capture"]["redactions"] == ["private_key_block"]
        assert_private_material_absent(engine, event_id)
    finally:
        engine.close()

    reopened = Engine(database, signer=signer, workdir=tmp_path)
    try:
        assert_private_material_absent(reopened, event_id)
    finally:
        reopened.close()


# Each detector has its own discriminator, including detectors that report the
# same public kind. A kind-keyed mapping would let one regex silently disappear
# while a sibling regex kept the shared sample green.
SECRET_PATTERN_SAMPLES = [
    ("github-token", "github_token", (
        "ghp_ABCDEFghijklmnopqrstuvwx123456",
        "gho_ABCDEFghijklmnopqrstuvwx123456",
        "ghu_ABCDEFghijklmnopqrstuvwx123456",
        "ghs_ABCDEFghijklmnopqrstuvwx123456",
        "ghr_ABCDEFghijklmnopqrstuvwx123456",
    )),
    ("github-pat", "github_pat", (
        "github_pat_" + "A" * 22 + "_" + "b" * 20,
    )),
    ("aws-access", "aws_access_key", ("AKIAIOSFODNN7EXAMPLE",)),
    ("aws-secret", "aws_secret", ("aws_secret_access_key = " + "A" * 40,)),
    ("private-key", "private_key_block", (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabcdefg\n-----END RSA PRIVATE KEY-----",
    )),
    ("slack", "slack_token", ("xoxb-123456789012-abcdefghijkl",)),
    ("jwt", "jwt", (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )),
    ("generic-assignment", "generic_assignment", ("password: hunter2secret",)),
    ("anthropic", "anthropic_key", ("sk-ant-" + "A" * 24,)),
    ("openai-modern", "openai_key", (
        "sk-proj-" + "A" * 40,
        "sk-svcacct-" + "B" * 40,
        "sk-admin-" + "C" * 40,
    )),
    ("openai-legacy", "openai_key", ("sk-" + "D" * 40,)),
    ("gitlab", "gitlab_token", ("glpat-" + "E" * 20,)),
    ("google", "google_api_key", ("AIza" + "F" * 35,)),
    ("npm", "npm_token", ("npm_" + "G" * 36,)),
    ("pypi", "pypi_token", ("pypi-" + "H" * 40,)),
    ("stripe-secret", "stripe_key", (
        "sk_live_" + "I" * 24,
        "sk_test_" + "J" * 24,
    )),
    ("stripe-restricted", "stripe_key", (
        "rk_live_" + "K" * 24,
        "rk_test_" + "L" * 24,
    )),
]

# A secret does not stop being a secret because of what sits beside it. `_` and
# `-` are word/identifier characters and diff markers, which is exactly where
# the word-boundary anchors used to suppress the match.
NEIGHBOURS = ["{s}", "_{s}", "{s}_", "-{s}", "{s}-", "x{s}", "{s}x", "9{s}",
              "{s}9", "SECRET_{s}", "{s}_TAIL", "-{s}\n", "prefix_{s}_suffix"]


def test_every_secret_pattern_has_independent_samples():
    """Every regex has samples that no sibling detector can satisfy for it."""
    assert len(_SECRET_PATTERNS) == len(SECRET_PATTERN_SAMPLES)
    for index, ((kind, pattern), (_, expected_kind, samples)) in enumerate(
            zip(_SECRET_PATTERNS, SECRET_PATTERN_SAMPLES, strict=True)):
        assert kind == expected_kind
        for sample in samples:
            matches = [candidate_index for candidate_index, (_, candidate) in
                       enumerate(_SECRET_PATTERNS) if candidate.search(sample)]
            assert matches == [index], (kind, matches)


@pytest.mark.parametrize(
    ("case", "kind", "samples"), SECRET_PATTERN_SAMPLES,
    ids=[case for case, _, _ in SECRET_PATTERN_SAMPLES])
def test_a_secret_is_redacted_whatever_sits_next_to_it(case, kind, samples):
    for sample in samples:
        for neighbour in NEIGHBOURS:
            text = neighbour.format(s=sample)
            clean, kinds = redact_text(text)
            assert kind in kinds, (case, neighbour, kinds)
            # Not just "a kind was reported": no part of the literal may
            # survive, which is how a partially-redacted token leaves its tail.
            assert sample not in clean, (case, neighbour, clean)
            assert {finding["kind"] for finding in scan_secrets(text)} >= {kind}
