"""A negated assumption cue proposes nothing (ADR-132).

"We no longer assume X" extracted the same positive proposal as "We assume X",
so a sentence written to retire an assumption could, once confirmed, re-assert
it. A cue that is itself negated now abstains. Because this changes extraction
output for the same retained input, the extractor and processor identities
advance together.
"""

import pytest

from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.extraction import EXTRACTOR_VERSION, DeterministicExtractor
from tests.test_engine_e2e import REPOSITORY_ID, _issue

STATEMENT = "the upstream feed is ordered by timestamp"
AFFIRMED = f"We assume {STATEMENT}."
NEGATED = [
    f"We do not assume {STATEMENT}.",
    f"We don't assume {STATEMENT}.",
    f"We don’t assume {STATEMENT}.",
    f"We no longer assume {STATEMENT}.",
    f"We never assume {STATEMENT}.",
    f"We cannot assume {STATEMENT}.",
    f"We can't assume {STATEMENT}.",
    f"We must not assume {STATEMENT}.",
    f"We should not assume {STATEMENT}.",
    f"We decided not to assume {STATEMENT}.",
    f"Stop assuming {STATEMENT}.",
    f"We stopped assuming {STATEMENT}.",
    f"Do this without assuming {STATEMENT}.",
    f"The exporter never relies on the fact that {STATEMENT}.",
    f"The exporter no longer depends on {STATEMENT}.",
]


def _proposals(text):
    result = DeterministicExtractor().extract(text, source_authority="human_intent")
    return [(item.meta.get("proposed_kind"), item.statement) for item in result.items]


@pytest.mark.parametrize("text", NEGATED)
def test_negated_cue_proposes_no_assumption(text):
    # A prohibition or decision form ("We must not assume X") still proposes
    # the constraint or decision the author wrote; only the denied assumption
    # is withheld.
    assert [kind for kind, _ in _proposals(text) if kind == "assumption"] == []
    assert ("assumption", STATEMENT) not in _proposals(text)


def test_affirmed_cue_still_proposes_exactly_one_assumption():
    assert _proposals(AFFIRMED) == [("assumption", STATEMENT)]


def test_negated_cue_is_counted_as_an_abstention():
    result = DeterministicExtractor().extract(
        f"We no longer assume {STATEMENT}.", source_authority="human_intent")
    assert result.items == []
    assert result.abstained == 1


def test_mixed_paragraph_keeps_only_the_affirmed_assumption():
    text = f"We assume the cache is warm at startup. We no longer assume {STATEMENT}."
    assert _proposals(text) == [("assumption", "the cache is warm at startup")]


@pytest.mark.parametrize("text", [
    f"It is not clear yet, but we assume {STATEMENT}.",
    f"The docs say otherwise; we assume {STATEMENT}.",
    f"Nothing here is final. We assume {STATEMENT}.",
])
def test_a_negator_elsewhere_in_the_sentence_does_not_deny_the_cue(text):
    assert _proposals(text) == [("assumption", STATEMENT)]


def test_ingest_of_a_negated_cue_records_no_proposal():
    engine = Engine()
    engine.create_project("negated-cue", project_id="prj_negated_cue",
                          repository_id=REPOSITORY_ID)
    try:
        report = engine.ingest_github(
            "prj_negated_cue", "issues", "d1",
            _issue(1, f"We no longer assume {STATEMENT}."))
        assert [item for item in report["created"] if item["kind"] == "claim"] == []
        assert report["invalidations"] == []
    finally:
        engine.close()


def test_extractor_and_processor_identities_advance_with_the_rule():
    assert EXTRACTOR_VERSION == "1.5.0"
    assert DeterministicExtractor.version == "1.5.0"
    assert PROCESSOR_VERSION == "cce-processor/1.11.0"
