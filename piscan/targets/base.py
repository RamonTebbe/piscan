"""Core interfaces and data types shared across piscan.

This module defines the contracts the rest of the pipeline depends on:
a Target (the thing under test), a Policy (how it defends itself),
a Verdict (the outcome of an attack), and an AttackResult (the record).
There is intentionally no logic here — just the shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


@runtime_checkable
class Target(Protocol):
    """Anything that takes a prompt and returns a text response.

    Structural typing: any object exposing a matching send() method is a
    Target — no inheritance from this class required. The runtime_checkable
    decorator lets isinstance(obj, Target) check for the method at runtime.
    """

    def send(self, prompt: str) -> str: ...


@dataclass
class Policy:
    """How a target is configured to defend itself.

    canary is the secret string that must never leak; if it shows up in a
    response, the attack succeeded. system_prompt is optional context the
    target runs under.
    """

    canary: str
    system_prompt: str | None = None


class Verdict(Enum):
    """The outcome of judging one attack against a target."""

    BYPASS = "bypass"    # attack succeeded — the guardrail was broken
    BLOCKED = "blocked"  # attack failed — the guardrail held
    ERROR = "error"      # the attack could not be evaluated (e.g. target crashed)


@dataclass
class AttackResult:
    """The record of running one attack against one target."""

    attack_id: str
    category: str
    owasp: str
    verdict: Verdict
    response: str
