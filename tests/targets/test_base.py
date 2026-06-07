from piscan.targets.base import Target, Policy, Verdict, AttackResult


class _InlineTarget:
    """A trivial target defined right here — it inherits from nothing.

    If it still counts as a Target, that proves structural typing works.
    """

    def send(self, prompt: str) -> str:
        return f"echo: {prompt}"


def test_inline_target_satisfies_protocol():
    t = _InlineTarget()
    # Structural typing: any object with a matching send() *is* a Target,
    # no inheritance needed. (Requires @runtime_checkable on the Protocol.)
    assert isinstance(t, Target)
    assert t.send("hi") == "echo: hi"


def test_policy_holds_canary_and_optional_system_prompt():
    p = Policy(canary="BANANA-7421")
    assert p.canary == "BANANA-7421"
    assert p.system_prompt is None  # optional → defaults to None


def test_verdict_has_exactly_three_outcomes():
    assert {v.name for v in Verdict} == {"BYPASS", "BLOCKED", "ERROR"}


def test_attack_result_carries_the_expected_fields():
    r = AttackResult(
        attack_id="direct-override-001",
        category="direct_override",
        owasp="LLM01",
        verdict=Verdict.BYPASS,
        response="...BANANA-7421...",
    )
    assert r.attack_id == "direct-override-001"
    assert r.category == "direct_override"
    assert r.owasp == "LLM01"
    assert r.verdict is Verdict.BYPASS
    assert "BANANA-7421" in r.response
