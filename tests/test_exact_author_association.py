"""A GitHub author association is trusted only in GitHub's exact spelling
(ADR-134).

GitHub sends `author_association` in upper case. Text authority used to
upper-case the value before comparing it, so a payload carrying "owner" typed
its prose as maintainer intent and could raise an ADR-133 notice, while
command authorization compared exactly and refused the same value. Both now
compare exactly; any other spelling is untrusted content.
"""

import pytest

from causal_continuity_engine.engine import _AUTHORIZED_ASSOCIATIONS, PROCESSOR_VERSION
from causal_continuity_engine.github import TRUSTED_ASSOCIATIONS, normalize, text_authority

CANONICAL = sorted(TRUSTED_ASSOCIATIONS)
NOT_GITHUB_SPELLINGS = ["owner", "Owner", "oWNER", "member", "Member", "collaborator",
                        "Collaborator", "OWNER ", " OWNER", "OWNER\n"]
STAMP = "2026-07-29T10:00:00Z"
REPOSITORY = {"id": 1, "full_name": "o/r"}


def _payloads(association):
    issue = {"number": 5, "title": "T", "body": "B", "state": "open", "labels": [],
             "author_association": association, "created_at": STAMP}
    pull = {"number": 6, "title": "T", "body": "B", "state": "open", "merged": False,
            "author_association": association, "updated_at": STAMP,
            "base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}
    return {
        "issues": {"action": "opened", "issue": issue, "repository": REPOSITORY},
        "issue_comment": {
            "action": "created", "repository": REPOSITORY,
            "issue": {**issue, "author_association": "OWNER"},
            "comment": {"id": 7, "body": "B", "author_association": association,
                        "created_at": STAMP}},
        "pull_request": {"action": "opened", "pull_request": pull,
                         "repository": REPOSITORY},
        "pull_request_review": {
            "action": "submitted", "repository": REPOSITORY,
            "pull_request": {**pull, "author_association": "OWNER"},
            "review": {"id": 8, "body": "B", "state": "commented",
                       "author_association": association, "submitted_at": STAMP}},
    }


@pytest.mark.parametrize("association", CANONICAL)
def test_github_spellings_are_maintainer_intent(association):
    assert text_authority(association) == "human_intent"


@pytest.mark.parametrize("association", NOT_GITHUB_SPELLINGS)
def test_other_spellings_are_untrusted(association):
    assert text_authority(association) == "untrusted_content"


@pytest.mark.parametrize("association", [None, 1, b"OWNER", ["OWNER"], {"OWNER": 1}])
def test_non_text_associations_are_untrusted(association):
    assert text_authority(association) == "untrusted_content"


@pytest.mark.parametrize("event", ["issues", "issue_comment", "pull_request",
                                   "pull_request_review"])
@pytest.mark.parametrize("association", NOT_GITHUB_SPELLINGS)
def test_every_text_source_types_other_spellings_as_untrusted(event, association):
    envelope = normalize(event, "d1", _payloads(association)[event])
    assert envelope["authority"] == "untrusted_content"
    assert envelope["text_blocks"]
    assert all(block["authority"] == "untrusted_content"
               for block in envelope["text_blocks"])


@pytest.mark.parametrize("event", ["issues", "issue_comment", "pull_request",
                                   "pull_request_review"])
@pytest.mark.parametrize("association", CANONICAL)
def test_every_text_source_keeps_github_spellings_trusted(event, association):
    envelope = normalize(event, "d1", _payloads(association)[event])
    assert envelope["authority"] == "human_intent"
    assert all(block["authority"] == "human_intent"
               for block in envelope["text_blocks"])


@pytest.mark.parametrize("association", CANONICAL + NOT_GITHUB_SPELLINGS
                         + ["NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR"])
def test_text_trust_and_command_authorization_agree(association):
    assert ((text_authority(association) == "human_intent")
            == (association in _AUTHORIZED_ASSOCIATIONS))


def test_processor_identity_advances_with_the_rule():
    assert PROCESSOR_VERSION == "cce-processor/1.12.0"
