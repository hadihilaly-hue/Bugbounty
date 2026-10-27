# Real-run readiness

Honest assessment of what's missing or weak before pointing this harness at a
**real, authorized** bug-bounty program. Today everything has only run against
the local OWASP Juice Shop sandbox and in-process fixtures.

## Where the validator stands (measured)
Expanded Juice Shop evaluation (`bugbounty juiceshop-eval`, 18 labelled cases):

| set | precision | recall | fp_rate | tp | fp | tn | fn |
|---|---|---|---|---|---|---|---|
| supported classes | 1.00 | 1.00 | 0.00 | 10 | 0 | 6 | 0 |
| all cases | 1.00 | 0.83 | 0.00 | 10 | 0 | 6 | 2 |

**Reading it honestly:** the validator is *precise* (zero false positives here)
and reliable on the classes it has executable proofs for (SQLi/auth via rerunnable
HTTP, IDOR via two accounts, DOM XSS via a real browser, and sensitive-file
exposure via generic HTTP oracle). The two misses are **coverage gaps**, not
precision problems: time-based/blind SQLi (no timing/boolean oracle) and stored
XSS (needs write-then-render; the harness only loads one URL). On a real program
whose bug mix includes those plus CSRF, SSRF, JWT/alg confusion, and business
logic, **recall will be well below these sandbox numbers.** The 3/3-vs-3/3 Phase 1
benchmark proved plumbing; this larger set shows the real edges.

## Gaps for a real run (prioritised)

### HIGH — Live auth / session handling
The IDOR/auth proofs log in via a static `login_spec` (JSON body + a JSON token
path) and a gitignored creds file. Real targets break this:
- OAuth/SSO/MFA login flows, CSRF tokens on forms, cookie-based sessions.
- No cookie jar across steps beyond a single httpx client, no CSRF-token
  extraction/chaining, no token refresh, no re-auth on mid-run 401/expiry.
- Anti-automation (captcha, device checks).
**Needed:** a pluggable auth module (cookie + header + refresh), CSRF chaining,
session-expiry recovery. Until then, authenticated testing on real targets is
unreliable.

### HIGH — Rate limiting / politeness
The orchestrator caps concurrency, total requests, wall-clock, tokens, and USD,
but there is **no per-host pacing**: recon and harnesses fire requests with no
delay, jitter, or `429`/`Retry-After` backoff. On a live program this risks
tripping WAFs/rate limits, getting the tester blocked, or violating program rules.
**Needed:** per-target RPS limit + jittered delay + exponential backoff on 429,
and a configurable politeness budget per host.

### MEDIUM — Finder false-positive volume + unproven classes
The LLM finder is deliberately liberal (expect the oft-cited ~80% FP). The
validator gate is what makes that safe — only CONFIRMED reaches the queue — but
candidates in classes with no harness (stored XSS, blind injection, CSRF, JWT,
business logic) come back UNCONFIRMED, not CONFIRMED. That's correct (never a
false confirm) but means a **human-triage backlog** of plausible-but-unproven
findings on a real target. Mitigations in place: confirmed-first dashboard,
UNCONFIRMED flagged "needs a human". **Needed:** finder precision tuning + more
harnesses, or an explicit "manual-triage" lane.

### MEDIUM — Proof-harness coverage
No executable proof for: stored/second-order XSS, blind/time-based SQLi, CSRF,
SSRF against a live callback, JWT/alg-confusion, auth logic (password reset,
IDOR on write), business-logic abuse. These are either missed (fn) or left to
humans.

### MEDIUM — Secrets & evidence hygiene
Per-target creds live in a gitignored YAML; a real run needs proper secret
storage. Stored evidence (full HTTP bodies, screenshots) may capture PII/secrets
from a live target — no redaction today.

### LOW — Nuclei signal not installed
The Nuclei wrapper degrades gracefully but the binary isn't present, so that web
signal is currently a no-op.

## Guardrails that ARE solid (keep relying on them)
- Allowlist-only, fail-closed scope (`scope.py` `decide`): unknown target or no
  in-scope match → blocked; out-of-scope beats in-scope.
- `DRY_RUN` defaults **on**; active payloads need global DRY_RUN off **and**
  target `dry_run` off **and** kill switch off (`config.py` `active_payloads_allowed`).
- No auto-submit anywhere; scope auto-ingest blocked (`intake.py` raises).
- Hard budget caps + credit-window warnings + kill switch (flag or file).

## Recommendation
Before a real program: (1) add live auth/session handling, (2) add per-host rate
limiting + 429 backoff, (3) keep `DRY_RUN` on for a first **supervised** pass
(recon + static only), clearing the gates only for a single known endpoint you
watch live, (4) treat unproven-class findings as manual triage, not misses.
