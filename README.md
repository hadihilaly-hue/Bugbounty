# bugbounty — validator-first AI bug-bounty harness

An **authorized** bug-bounty vulnerability-discovery harness. It only runs against
targets you have explicitly authorized (published scope + safe harbor) or code you
own. Authorization is enforced in code, not just documented.

> Status: **Phase 1** — the adversarial **validator** is implemented and tuned
> against OWASP Juice Shop ground truth (precision 1.00 / recall 1.00 on the
> built-in benchmark). Phase 0 guardrails and scope enforcement remain in place.
> Finder, orchestrator, dashboard, and overnight jobs land in later phases.

## Hard guardrails

- **Authorized targets only.** Nothing runs against a host that is not matched by an
  `in_scope` entry in an allowlist (`targets.yaml`) you control. Unmatched hosts and
  anything in `out_of_scope` are skipped and logged. Scope checks **fail closed**.
- **Never auto-submit.** The harness only produces reports for your review. It never
  files anything to any platform. Submission is a manual step you do by hand.
- **No destructive / out-of-scope actions.** Rate-limited, respects program limits,
  no DoS, no data exfiltration beyond minimal proof, no third-party testing.
- **`DRY_RUN=true` is the default.** In dry-run the harness does recon + static
  analysis + reasoning but sends **no** active exploit payloads. Active payloads
  require the global `DRY_RUN` off **and** the specific target's `dry_run` cleared;
  a kill switch overrides both.

## Architecture (validator-first)

Built in this order of effort: **validator > orchestrator > finder**. Most findings an
LLM produces are false positives; the validator is what makes this worth anything.

1. **Finder** — generates candidate findings from cheap deterministic signal
   (Semgrep, Nuclei, recon) plus Anthropic reasoning.
2. **Validator** — a separate, adversarial agent whose only job is to *disprove* each
   finding with a concrete, re-runnable PoC. Statuses: `CONFIRMED` / `UNCONFIRMED` /
   `REJECTED`. Only `CONFIRMED` reaches your review queue by default.
3. **Orchestrator** — runs targets with a concurrency cap, kills weak targets early,
   persists everything to SQLite, enforces the budget caps and kill switch.

## Layout

```
targets.yaml            # allowlist: the only thing that authorizes a target
secrets/                # gitignored per-target creds / cookies
src/bugbounty/
  config.py             # DRY_RUN default, budget caps, kill switch
  scope.py              # targets.yaml models + allowlist enforcement
  intake.py             # scope-text -> targets.yaml entry (Phase 4)
  recon/ signal/ finder/ validator/ orchestrator/ dashboard/
  cli.py
tests/
```

## Setup

```bash
uv sync --extra finder --group dev   # or plain `uv sync` for the Phase 0 core
uv run bugbounty version
uv run bugbounty config               # show effective guardrails
uv run bugbounty targets              # list allowlist entries
uv run bugbounty scope "OWASP Juice Shop (local sandbox)" localhost
```

`scope` exits non-zero when a host is blocked, so it is safe to gate scripts on it.

## Validator

The validator refuses to trust the finder. A candidate is only `CONFIRMED` when a
proof harness *executes* against the target and its oracle demonstrates the bug;
otherwise it is `REJECTED` (disproven) or `UNCONFIRMED` (no conclusive proof could
run — dry-run, missing creds, target down, unsupported class). Only `CONFIRMED`
reaches the review queue.

Proof harnesses (one per class):

- **XSS** — drives a real headless browser (Playwright); requires actual script
  execution (a JS dialog or console marker), not mere reflection, and saves a
  screenshot as evidence.
- **IDOR** — two accounts; proves attacker account A can read victim account B's
  object.
- **SSRF / auth / injection** — a re-runnable HTTP PoC with an explicit success
  oracle; emits the equivalent `curl`.

Every harness that sends an active payload is gated by the same dry-run / kill-switch
rules as the rest of the harness, so in dry-run it returns `UNCONFIRMED` rather than
faking a result. Errors never yield `CONFIRMED`.

```bash
uv sync --extra dynamic --group dev          # playwright + httpx for live proofs
uv run playwright install chromium

# validate a YAML file of candidate findings
uv run bugbounty validate candidates.yaml

# measure validator precision/recall against a local Juice Shop sandbox
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
DRY_RUN=false uv run bugbounty bench-juiceshop
```

## Target intake

Add programs to `targets.yaml` yourself — the harness never scrapes or auto-ingests.
Each entry requires a `safe_harbor_url` and `in_scope` assets. See the commented
example in `targets.yaml` for the full schema (`platform`, `ai_policy`, `pays_cash`,
`in_scope` / `out_of_scope` globs, `auth`, `dry_run`).

## Auth

Post-auth bugs (IDOR, broken access control, account takeover) need credentials. Put
per-target creds or live browser cookies in `secrets/<target>.yaml` (gitignored); see
`secrets/example.yaml.example`. Two accounts enable access-control testing.
