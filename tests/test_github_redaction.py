"""GitHub webhook verification/normalization and redaction/capture modes."""

import hashlib
import hmac
import json

import pytest

from causal_continuity_engine.github import (
    WebhookError,
    continuity_conclusion,
    normalize,
    text_authority,
    verify_signature,
)
from causal_continuity_engine.redaction import apply_capture_mode, redact_text, scan_secrets


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

    def test_unknown_mode_rejected(self):
        with pytest.raises(ValueError):
            apply_capture_mode({}, "everything")
