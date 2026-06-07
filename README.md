# piscan

> Prompt-injection robustness scanner for **your own** LLM apps.

`piscan` measures how vulnerable an LLM application is to prompt-injection
attacks. It runs a suite of attacks against a target, judges whether each one
broke the system's guardrails, and reports an **Attack Success Rate (ASR)** and
**robustness score** — mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

🚧 **Status: work in progress.** Built module by module — see `docs/` for the
design spec and implementation plan.

## Why

Defensive security research and red-teaming of LLM apps you own. The goal is a
testable, reproducible way to ask "how robust is *my* system prompt?" and to
prove a scanner can tell a leaky target from a hardened one.

## Scope & ethics

This is a **defensive** tool. It is meant to be pointed at LLM applications you
own or are explicitly authorized to test.

- ✅ Test your own targets — a local model (via [Ollama](https://ollama.com/)) or
  the built-in deterministic mock target.
- ✅ Synthetic canaries only — no real secrets, no genuinely harmful output.
- ❌ Do **not** point it at third-party production systems, attempt to bypass
  rate limits, or extract proprietary models.

The default target runs against a **local** model — no API key, no cost, no
third-party Terms of Service involved.

## Roadmap

- Deterministic backbone: mock target → attack loader → canary judge → runner →
  report → CLI, fully tested in CI.
- Ollama adapter + leaky-vs-hardened empirical validation.
- Future work: LLM-as-judge (with a precision/recall experiment), more target
  adapters (Claude, OpenAI), more attack categories, richer reporting.

## License

MIT — see `LICENSE`.
