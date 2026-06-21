"""Tests for the report layer — aggregate AttackResults into ASR + robustness
and render them as Markdown.

The two headline numbers:
  ASR (Attack Success Rate) = bypass / (bypass + blocked)
  Robustness Score          = 1 - ASR

ERROR verdicts mean an attack could not be evaluated, so they are kept out of
the ASR denominator and reported separately — otherwise a flaky target would
flatter (or wreck) the score without any real evidence.
"""

from piscan.report.markdown import summarize, render_markdown
from piscan.targets.base import AttackResult, Verdict


def _result(category: str, verdict: Verdict) -> AttackResult:
    # Build an AttackResult from just the two fields the report cares about
    # (category + verdict); the rest is throwaway metadata so each test reads
    # as the scenario it describes.
    return AttackResult(
        attack_id="x",
        category=category,
        owasp="LLM01",
        verdict=verdict,
        response="",
    )


def test_overall_asr_and_robustness_for_two_bypass_two_blocked():
    results = [
        _result("injection", Verdict.BYPASS),
        _result("injection", Verdict.BYPASS),
        _result("leak", Verdict.BLOCKED),
        _result("leak", Verdict.BLOCKED),
    ]

    summary = summarize(results)

    assert summary.total == 4
    assert summary.asr == 0.5
    assert summary.robustness == 0.5


def test_asr_is_computed_per_category():
    results = [
        _result("injection", Verdict.BYPASS),
        _result("injection", Verdict.BYPASS),   # injection: 2 bypass / 2 -> 1.0
        _result("leak", Verdict.BLOCKED),
        _result("leak", Verdict.BLOCKED),        # leak: 0 bypass / 2 -> 0.0
    ]

    summary = summarize(results)

    assert summary.categories["injection"].asr == 1.0
    assert summary.categories["leak"].asr == 0.0


def test_errors_are_excluded_from_asr_and_counted_separately():
    results = [
        _result("injection", Verdict.BYPASS),
        _result("injection", Verdict.BLOCKED),
        _result("injection", Verdict.ERROR),
    ]

    summary = summarize(results)

    # ASR over evaluated attacks only: 1 bypass / (1 bypass + 1 blocked) = 0.5
    assert summary.evaluated == 2
    assert summary.asr == 0.5
    assert summary.error == 1
    assert summary.total == 3


def test_all_errors_give_zero_asr_without_dividing_by_zero():
    results = [_result("injection", Verdict.ERROR)]

    summary = summarize(results)

    assert summary.asr == 0.0
    assert summary.robustness == 1.0
    assert summary.error == 1


def test_render_markdown_includes_scores_categories_and_errors():
    results = [
        _result("injection", Verdict.BYPASS),
        _result("injection", Verdict.BLOCKED),  # evaluated: 1 bypass / 2 -> 50.0%
        _result("leak", Verdict.ERROR),
    ]

    md = render_markdown(results)

    assert "Attack Success Rate (ASR)" in md
    assert "Robustness Score" in md
    assert "50.0%" in md          # overall ASR rendered as a percentage
    assert "injection" in md      # category rows present
    assert "leak" in md
    assert "Error" in md          # errors surfaced separately, not hidden
