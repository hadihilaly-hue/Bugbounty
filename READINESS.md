# Real-run readiness

Honest assessment of what's missing or weak before pointing this harness at a
**real, authorized** bug-bounty program. Today everything has only run against
local sandboxes (OWASP Juice Shop, DVWA, crAPI) and in-process fixtures.

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

### RESOLVED (this branch) — Live auth / session handling
A shared session layer (`src/bugbounty/net/session.py`, `SessionManager`) now
holds a real authenticated session across a run:
- Cookie capture/reuse across requests, robust to apps that re-set a cookie name
  mid-flow (last value wins — e.g. DVWA's session regeneration on login).
- CSRF-token detection + inclusion for form logins (`login.csrf_field`).
- Form (cookie) and JSON/token (bearer) login modes, configured per target via
  the `auth.login` block in `targets.yaml`; creds stay in gitignored
  `secrets/<target>.yaml`, with 2+ accounts for the IDOR two-account test.
- Re-authentication on mid-run session expiry (401 or an expiry marker) without
  losing the run.
- Manual handed-in session: paste a live browser cookie / bearer token in
  secrets and the agent uses it directly, skipping headless login — the path for
  anti-bot defeat.
- MFA is **detected and surfaced, never faked** (`login.mfa_marker`/`mfa_status`
  or `auth.mfa_required`); supply a live session to proceed.
Verified against **DVWA** — CSRF `user_token` + cookie session, a harder target
than Juice Shop's token API — at precision/recall/fp 1.00/1.00/0.00, plus unit
tests for cookie reuse, CSRF inclusion, re-auth on expiry, MFA detection, and
manual-cookie injection.

**Still weak:** full OAuth/SSO redirect dances, WebAuthn/complex MFA, and
aggressive anti-bot (captcha / device fingerprinting) are not automated — use the
manual handed-in-session path for those. The validator **proof harnesses**
(`validator/harnesses/*`) still open their own httpx clients, so session reuse
and pacing there are not yet wired (those files are being reworked on a separate
branch); today the session is injected into HTTP-PoC candidates via request
headers, and recon + the eval adapters use the shared paced/authenticated
client.

### RESOLVED (this branch) — Rate limiting / politeness
`src/bugbounty/net/pacing.py` adds per-host pacing + backoff on top of the
existing global budget caps, applied to every request made through
`net.build_client` (recon and the eval adapters), **including DRY_RUN recon**:
- Per-host request pacing (clock spacing at a conservative default
  `BB_PER_HOST_RPS=1.0`) with jitter, tracked independently per host.
- `429` handling: honours `Retry-After` (delta-seconds or HTTP-date), otherwise
  capped exponential backoff, retrying up to `BB_MAX_RETRIES_429`.
- The global per-run request / concurrency / USD / wall-clock caps and the kill
  switch are unchanged and still apply on top.
Unit-tested: per-host spacing, host independence, `Retry-After` parsing,
honour-`Retry-After`, exponential backoff, and give-up-after-max-retries.

**Still weak:** the validator proof harnesses open their own httpx clients
(separate branch), so their request path isn't paced yet — point them at
`net.build_client` once that branch lands. No adaptive throttling beyond the
fixed per-host rate.

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
Before a real program: (1) live auth/session handling and (2) per-host rate
limiting + 429 backoff are now in place (this branch) — adopt them inside the
validator proof harnesses once that parallel branch lands; (3) keep `DRY_RUN` on
for a first **supervised** pass (recon + static only), clearing the gates only
for a single known endpoint you watch live; (4) treat unproven-class findings as
manual triage, not misses; (5) use the manual handed-in-session path for
OAuth/SSO/MFA/anti-bot targets.
