"""The runner: drive every attack against one target and collect the verdicts.

The runner is the orchestration layer. It knows only the interfaces — a Target
(anything with send()), a list of Attacks (data), and a Policy (which carries
the canary to judge against). It deliberately knows nothing about *which* target
it is talking to, so the same loop works for the mock, a local Ollama model, or
a hosted API.

If a target raises while handling one attack, that attack is recorded as an
ERROR and the loop moves on — one broken probe must never sink the whole run.
"""

from __future__ import annotations

from piscan.attacks.loader import Attack
from piscan.judge.canary import judge
from piscan.targets.base import AttackResult, Policy, Target, Verdict


def run(target: Target, attacks: list[Attack], policy: Policy) -> list[AttackResult]:
    """Run every attack against the target and return one AttackResult each."""
    results: list[AttackResult] = []
    for attack in attacks:
        try:
            response = target.send(attack.prompt)
            verdict = judge(response, policy.canary)
        except Exception:
            # Any failure of a single probe (crash, timeout, network error) is
            # contained here so the batch survives. We catch Exception, not bare
            # except, so KeyboardInterrupt/SystemExit still abort the run.
            response = ""
            verdict = Verdict.ERROR
        results.append(
            AttackResult(
                attack_id=attack.id,
                category=attack.category,
                owasp=attack.owasp,
                verdict=verdict,
                response=response,
            )
        )
    return results
