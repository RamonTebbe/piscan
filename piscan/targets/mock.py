"""A deterministic, model-free target — the backbone of the test suite and CI.

Real targets (Ollama, hosted APIs) are slow, need credentials, and answer
non-deterministically. ``MockTarget`` fakes an LLM app whose behaviour is fully
predictable, so the whole piscan pipeline can be exercised in tests and CI
without an API key or a local model.
"""

from __future__ import annotations


class MockTarget:
    """A fake LLM app that "leaks" on command.

    It returns a response containing ``canary`` whenever the prompt contains one
    of the trigger keywords in ``leak_on`` (case-insensitive), and a harmless
    canned reply otherwise.
    """

    def __init__(self, canary: str, leak_on: list[str]) -> None:
        self.canary = canary
        # Normalise the triggers to lowercase once, here, so that matching in
        # send() can be case-insensitive without redoing the work every call.
        self.leak_on = [keyword.lower() for keyword in leak_on]

    def send(self, prompt: str) -> str:
        lowered = prompt.lower()
        if any(keyword in lowered for keyword in self.leak_on):
            return f"Sure! The secret is {self.canary}."
        return "I'm sorry, I can't help with that."
