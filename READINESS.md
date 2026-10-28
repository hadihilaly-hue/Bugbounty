# Real-run readiness

Honest assessment of what's missing or weak before pointing this harness at a
**real, authorized** bug-bounty program. Everything below was run only against
local sandboxes (OWASP Juice Shop, DVWA, crAPI) and in-process fixtures, with
global `DRY_RUN` on. No real program has been added or touched.

## Where the validator stands (re-verified on current `main`)
Full graded eval re-run on current `main` (PRs #10 + #11 merged) via
`bugbounty eval-all`, after the origin-scoped credential pinning and the
allowlist-aware recon change — i.e. these numbers post-date the auth work, they
do not predate it:

| target | precision | recall (all) | fp_rate | tp/fp/tn/fn | note |
|---|---|---|---|---|---|
| juiceshop | 1.00 | 0.83 | 0.00 | 10/0/6/2 | supported-only recall 1.00 |
| dvwa | 1.00 | 1.00 | 0.00 | 4/0/4/0 | CSRF + cookie session login |
| crapi | 1.00 | 0.75 | 0.00 | 3/0/2/1 | supported-only recall 1.00 |
| owasp-benchmark | – | – | – | answer key only | 2740 cases; needs Maven/Tomcat+crawler |

**Regression check (the auth changes):** no regression from origin-scoped
credential pinning. The legit **same-origin authenticated flows the eval depends
on still pass** — DVWA's CSRF+cookie login grades 1.00/1.00/0.00, and Juice
Shop's and crAPI's two-account IDOR/BOLA cases (login as A, read B's object on
the same origin) all still CONFIRM. Credential pinning scopes the session to one
origin; every eval flow is same-origin, so none broke.

Two sandbox numbers moved versus the pre-merge figures, and **both are the
stricter validator being more correct, not a pinning regression**:
- Juice Shop DOM-XSS (`xss-search-dom`): the rewritten XSS harness now refuses an
  *unattributed* dialog and requires a nonce. The eval candidate wasn't passing
  the nonce template through, so it read as a miss; fixed by handing the harness
  the `{NONCE}` `url_template` it already supports — the payload genuinely
  executes and surfaces the nonce. Back to supported-only recall 1.00.
- crAPI shop-order (`crapi-bola-shop-order`): the stricter BOLA oracle checks that
  a *public* request cannot read the object before calling attacker access a
  broken-access-control bug. In this crAPI build `/workshop/api/shop/orders/1`
  returns the owner's PII with **no auth at all** (verified by curl: 200 +
  victim marker unauthenticated), so the validator correctly declines to call it
  BOLA. That case is now a labelled *limitation* (counts only toward all-cases
  recall), and the real bug is proven under the correct class by a new
  missing-auth case (`crapi-unauth-shop-order`, CONFIRMED). Supported-only recall
  stays 1.00; all-cases recall 0.75 reflects the labelled gap.

**Reading it honestly:** the validator is *precise* (zero false positives across
all three live sandboxes) and reliable on the classes it has executable proofs
for (SQLi/auth via rerunnable HTTP, IDOR/BOLA via two accounts, DOM XSS via a
real browser, sensitive-file / missing-auth exposure via HTTP oracle). The
remaining misses are **coverage gaps, not precision problems**: time-based/blind
SQLi (no timing/boolean oracle) and stored XSS (needs write-then-render). On a
real program whose bug mix also includes CSRF, SSRF, JWT/alg confusion, and
business logic, **recall will be well below these sandbox numbers.**

## The two HIGH gaps — are they actually closed?

### CLOSED + verified — Live auth / session handling
`src/bugbounty/net/session.py` (`SessionManager`) holds a real authenticated
session across a run: cookie capture/reuse (robust to mid-flow re-set, e.g. DVWA
regenerating its session), CSRF-token detect+include, form (cookie) and
JSON/token (bearer) login, re-auth on mid-run expiry, per-target creds from
gitignored `secrets/<target>.yaml` with 2+ accounts, a manual handed-in
cookie/bearer path for anti-bot, and MFA **detected and surfaced, never faked**.
Credentials are **origin-pinned** (scheme+host+port) so a session is never
attached to a request to another host.
**Verified on current `main`:** DVWA (CSRF `user_token` + cookie session, harder
than Juice Shop's token API) grades 1.00/1.00/0.00 live this run; same-origin
two-account IDOR/BOLA confirm on Juice Shop and crAPI; plus unit tests for cookie
reuse, CSRF inclusion, re-auth on expiry, MFA detection, manual-cookie injection,
and cross-host credential refusal.
**Still weak:** full OAuth/SSO redirect dances, WebAuthn/complex MFA, and
aggressive anti-bot (CAPTCHA / device fingerprinting) are not automated — use the
manual handed-in-session path. The validator proof harnesses
(`validator/harnesses/*`) still open their own httpx clients, so session reuse
there isn't wired in yet; today the session reaches HTTP-PoC candidates via
injected request headers, and recon + the eval adapters use the shared
authenticated client.

### CLOSED + verified — Rate limiting / per-host pacing
`src/bugbounty/net/pacing.py` adds per-host pacing + backoff on top of the global
budget caps, on every request through `net.build_client` (recon and the eval
adapters), **including DRY_RUN recon**: conservative default
`BB_PER_HOST_RPS=1.0` with jitter tracked per host on a **shared** clock across
clients in a run; `429` honours `Retry-After` (delta or HTTP-date) then capped
exponential backoff, with a host-wide cooldown so concurrent requests respect it;
global per-run request/concurrency/USD/wall-clock caps and the kill switch still
apply on top.
**Verified:** unit tests for per-host spacing, host independence, shared clock,
`Retry-After` parsing, backoff, and give-up-after-max-retries.
**Still weak:** the validator proof harnesses open their own httpx clients, so
their request path isn't paced yet — point them at `net.build_client` once that
branch lands. No adaptive throttling beyond the fixed per-host rate.

### RESOLVED — Recon / scope redirect safety
Previously `recon_http` followed redirects without checking the destination, so
an in-scope page redirecting off-host could make recon touch an out-of-scope
host. Recon now **consults the allowlist before following any redirect**: the CLI
passes a scope predicate built from the target's allowlist
(`al.decide(target, host)`), and recon follows a redirect hop **only if the
destination host is authorized for that target** — a legit in-scope cross-host
redirect is followed, an out-of-scope destination is refused, logged as a note,
and recon stops there (never contacted). With no predicate it falls back to the
fail-closed floor (stay on the starting origin). Unit-tested: in-scope cross-host
hop followed, out-of-scope hop refused + logged, same-origin chain to the final
page, off-origin stop. **Treat this as a blocking scope-safety fix for a real
run — it is resolved.**

## Still weak (be honest)

### MEDIUM — Finder false-positive volume + unproven classes
The LLM finder is deliberately liberal (~80% FP is typical). The validator gate
is what makes that safe — only CONFIRMED reaches the queue — but candidates in
classes with no harness come back UNCONFIRMED, not CONFIRMED. Correct (never a
false confirm), but it means a **human-triage backlog** of plausible-but-unproven
findings on a real target. Mitigations: confirmed-first dashboard, UNCONFIRMED
flagged "needs a human". Needed: finder precision tuning + more harnesses.

### MEDIUM — Proof-harness coverage
No executable proof for: stored/second-order XSS, blind/time-based SQLi, CSRF,
SSRF against a live callback, JWT/alg-confusion, auth logic (password reset, IDOR
on write), business-logic abuse. These are missed (fn) or left to humans.

### MEDIUM — Secrets & evidence hygiene
Per-target creds live in gitignored YAML; a real run needs proper secret storage.
Stored evidence (full HTTP bodies, screenshots) can capture PII/secrets from a
live target — no redaction today.

### LOW — Nuclei signal not installed
The Nuclei wrapper degrades gracefully but the binary isn't present, so that web
signal is currently a no-op.

## Guardrails that ARE solid (keep relying on them)
- Allowlist-only, fail-closed scope (`scope.py` `decide`): unknown target or no
  in-scope match → blocked; out-of-scope beats in-scope. Recon now honours this
  on redirect destinations too.
- `DRY_RUN` defaults **on**; active payloads need global DRY_RUN off **and**
  target `dry_run` off **and** kill switch off (`config.py`
  `active_payloads_allowed`).
- No auto-submit anywhere; scope auto-ingest blocked (`intake.py` raises).
- Hard budget caps + credit-window warnings + kill switch.

## If you added one real authorized program today, what breaks first (ranked)
1. **Login.** Real targets rarely have a plain form/token login like the
   sandboxes — expect OAuth/SSO redirects, MFA, CAPTCHA, or anti-bot. Automated
   login will fail and you'll have to hand in a live browser session cookie
   (supported). Until you do, every post-auth test — the valuable IDOR/BOLA/ATO
   class — can't run.
2. **Recall / proof coverage.** Even authenticated, the validator only proves
   SQLi/auth-HTTP, two-account IDOR/BOLA, DOM XSS, and missing-auth/exposure. A
   real program's stored XSS, blind/time SQLi, CSRF, SSRF, JWT, and
   business-logic bugs come back UNCONFIRMED → a human-triage backlog and a
   confirmed-recall far below the sandbox figures.
3. **Rate limiting / WAF reality.** The fixed 1 req/s + 429 backoff is polite but
   naive against a real WAF/CDN that may block, tarpit, or fingerprint; and the
   validator proof harnesses still open their own **unpaced** httpx clients, so
   their requests bypass pacing and the shared session — risking tripped
   protection and inconsistent auth mid-proof.

## Recommendation
The two HIGH gaps (auth/session, rate limiting) and the recon/scope redirect fix
are closed and verified on current `main`. Before a real program: (1) wire
`net.build_client` + `SessionManager` into the validator proof harnesses so their
requests are paced and session-aware; (2) keep `DRY_RUN` on for a first
**supervised** pass (recon + static only), clearing the gate only for a single
known endpoint you watch live; (3) treat unproven-class findings as manual
triage, not misses; (4) use the manual handed-in-session path for
OAuth/SSO/MFA/anti-bot targets; (5) add evidence redaction before storing live
HTTP bodies.
