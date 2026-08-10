"""The benchmark harness itself: a scenario crash must not silence the run.

These test the runner, not the scenarios. The scenarios are the instrument;
this is the frame it hangs on, and a frame that drops the instrument on the
floor when one part breaks reports nothing at all.
"""

from __future__ import annotations

from benchmarks.continuitybench import run as runner


def _passing(name, metrics):
    def scenario():
        return {"name": name, "checks": [("did the thing", True)],
                "metrics": dict(metrics)}
    scenario.__name__ = name
    return scenario


def _exploding(name):
    def scenario():
        raise KeyError("req_91ec7cad")
    scenario.__name__ = name
    return scenario


def test_a_scenario_that_raises_is_a_failure_not_an_aborted_run(monkeypatch):
    """One uncaught exception used to abort the whole run and emit no metrics.

    No metrics reads exactly like never having run, which is the confusion
    this project exists to prevent. `prose_may_mandate=False` reaches this
    path today: `changed_requirement` raises `KeyError`.
    """
    monkeypatch.setattr(runner, "ALL_SCENARIOS", [
        _passing("healthy", {"invalidation_recall": 1.0}),
        _exploding("broken"),
    ])
    report = runner.run()

    assert [r["name"] for r in report["scenarios"]] == ["healthy", "broken"]
    broken = report["scenarios"][1]
    assert broken["crashed"] is True
    assert broken["passed"] is False
    assert "KeyError" in broken["checks"][0][0]
    # The crash counts against continuity_success_rate rather than vanishing.
    assert report["metrics"]["continuity_success_rate"] == 0.5


def test_a_crash_cannot_make_the_remaining_metrics_easier(monkeypatch):
    """Averages are taken only over scenarios that reported a metric.

    So a scenario that would have dragged an average down improves it by
    crashing. Reporting that average as a PASS would let the benchmark award
    itself a better score for breaking, which is the one thing it must never
    do.
    """
    monkeypatch.setattr(runner, "ALL_SCENARIOS", [
        _passing("healthy", {"invalidation_recall": 1.0}),
        _exploding("would_have_scored_badly"),
    ])
    report = runner.run()

    # The surviving scenario alone averages to a perfect score...
    assert report["metrics"]["critical_invalidation_recall"] == 1.0
    # ...and the gate still refuses to call that a pass.
    assert report["gates"]["critical_invalidation_recall"] == "incomplete"
    # continuity_success_rate is exempt: a crash is a failure in its
    # denominator, so it stays honest as a lower bound.
    assert report["gates"]["continuity_success_rate"] in ("PASS", "FAIL")


def test_a_clean_run_still_reports_pass_and_fail(monkeypatch):
    """The guard must not turn ordinary runs into permanent 'incomplete'."""
    monkeypatch.setattr(runner, "ALL_SCENARIOS", [
        _passing("healthy", {"invalidation_recall": 1.0}),
    ])
    report = runner.run()

    assert not any(r.get("crashed") for r in report["scenarios"])
    assert report["gates"]["critical_invalidation_recall"] == "PASS"
    assert report["gates"]["continuity_success_rate"] == "PASS"
