"""Benchmark-owned Engines close even when scenario setup or authority refuses."""

import sqlite3

import pytest

from benchmarks.continuitybench import run as runner
from benchmarks.continuitybench import scenarios


@pytest.fixture
def constructed_engines(monkeypatch):
    original = scenarios.Engine
    captured = []

    def track(*args, **kwargs):
        instance = original(*args, **kwargs)
        captured.append(instance)
        return instance

    monkeypatch.setattr(scenarios, "Engine", track)
    try:
        yield original, captured
    finally:
        # Keep baseline failures deterministic without leaking the planted handles.
        for instance in captured:
            instance.close()
        runner._cleanup_workdirs()


@pytest.mark.parametrize("failure", [None, "producer", "project"],
                         ids=["healthy", "producer-refusal", "fixture-refusal"])
def test_canonical_runs_close_every_engine_and_clear_registries(
        monkeypatch, constructed_engines, failure):
    original, captured = constructed_engines
    if failure is not None:
        def refuse(*args, **kwargs):
            raise PermissionError("planted " + failure + " refusal")

        method = "record_authority_decision" if failure == "producer" else "create_project"
        monkeypatch.setattr(original, method, refuse)

    for iteration in range(2):
        report = runner.run()
        batch = captured[iteration * 11:]
        assert len(batch) == 11
        results = report["scenarios"]
        assert len(results) == 11
        assert {result["name"] for result in results} == {
            scenario.__name__ for scenario in scenarios.ALL_SCENARIOS}
        assert len(report["gates"]) == 6
        if failure is None:
            assert all(result["passed"] and not result.get("crashed") for result in results)
            assert set(report["gates"].values()) == {"PASS"}
        else:
            passed = {result["name"] for result in results if result["passed"]}
            expected = {"prompt_injection", "replay_to_eval"} if failure == "producer" else set()
            assert passed == expected
            failed = [result for result in results if not result["passed"]]
            assert len(failed) == 11 - len(expected)
            assert all(result.get("crashed") and
                       "planted " + failure + " refusal" in result["checks"][0][0]
                       for result in failed)
            assert report["metrics"]["continuity_success_rate"] == len(expected) / 11
            assert report["gates"] == {
                name: "FAIL" if name == "continuity_success_rate" else "no-data"
                for name in runner.MVP_TARGETS}

        live = []
        for scenario, instance in zip(scenarios.ALL_SCENARIOS, batch, strict=True):
            try:
                instance.store._conn.execute("SELECT 1")
            except sqlite3.ProgrammingError as exc:
                assert "closed database" in str(exc)
            else:
                live.append(scenario.__name__)
        assert live == [], f"{len(live)} live SQLite handles after run: {live}"
        assert scenarios._WORKDIRS == []
        if hasattr(scenarios, "_ENGINES"):
            assert scenarios._ENGINES == []
