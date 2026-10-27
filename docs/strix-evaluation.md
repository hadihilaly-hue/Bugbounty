# Strix evaluation: adopt as chassis, or build our own?

[`github.com/usestrix/strix`](https://github.com/usestrix/strix) — "autonomous AI
pentesting agents." Apache-2.0 core (`pip install strix-agent`), paid Cloud /
Enterprise tiers. Evaluated for this harness.

## What Strix is

Autonomous AI agents that run a target dynamically, find vulnerabilities, and
validate them with real PoCs. The OSS core ships:

- A per-run **Docker sandbox** and a **graph of agents** (recon / exploitation /
  post-exploitation) coordinated as a red team.
- A full offensive toolkit: HTTP intercept proxy (Caido), browser exploitation
  (Playwright), a shell, a Python exploit runtime, recon/OSINT, SAST+DAST.
- Targets: local code, GitHub repos, black-box web, and OpenAPI/Postman specs;
  grey-box authenticated testing via `--instruction`.
- LLM-agnostic via LiteLLM (`STRIX_LLM` + `LLM_API_KEY`); a local `strix view`
  web viewer; CI/CD and MCP-server integration.
- An explicit **authorized-use-only** warning.

It overlaps almost entirely with what this project does: recon → exploit →
validate-with-PoC, plus a local viewer.

## Decision: replace (build our own), reuse the same primitives, keep Strix as an optional candidate source

We are **not** adopting Strix as the chassis. Reasons, specific to this project's
requirements:

1. **The product is the gate, not the agent.** Our entire value proposition is the
   *adversarial validator* with a hard `CONFIRMED / UNCONFIRMED / REJECTED` model
   where only `CONFIRMED` (an executed, reproducible proof) reaches the queue, and
   a fail-closed `targets.yaml` allowlist. Strix's validation is an agent loop; to
   get our guarantees we would have to fence an opaque autonomous agent rather than
   own the deterministic gate. Owning the gate is the point.
2. **Guardrails must be enforced in code.** We require dry-run default, per-target
   dry-run, a global kill switch, hard token/request/wall-clock/USD caps, credit
   50/75/90% warnings, no auto-submit, and fail-closed scope. These live in
   `config.py` / `scope.py` / `orchestrator/budget.py`. Wrapping Strix's agent and
   Docker-sandbox loop around these controls is far harder than building a thin
   control plane we fully own.
3. **Budget predictability.** Strix is an autonomous multi-agent loop with its own
   LLM config and a Docker sandbox per run; its spend is driven by the agent, not
   by us. Our validator's proofs are deterministic and ~free, so credit is spent
   only in the finder, where we meter it per job. That is exactly the control the
   time-boxed credit window needs.
4. **Weight.** Caido proxy, multi-agent orchestration, per-run Docker image — a lot
   of surface we neither need nor can fully reason about for reproducibility.

What we **do** take from Strix:

- It uses **Nuclei** and **Playwright** under the hood; we use those same
  primitives directly (lower level, fully under our control) rather than through
  an agent.
- Its `strix view` local viewer and SKILL.md "agent-ready" packaging validate our
  Phase 4 dashboard direction.
- **Optional roadmap integration:** add a Strix *candidate source* that runs
  `strix -n --target <url> --scan-mode quick` and feeds its findings into our
  pipeline **as unproven candidates**, which our adversarial validator then
  re-proves. That buys Strix's breadth while our gate stays authoritative — the
  right way to use Strix here, as a finder input, not the chassis.

## Summary

Build our own finder/validator/orchestrator; reuse Nuclei + Playwright directly;
keep "Strix as an extra candidate source behind the validator" as an optional
future adapter.
