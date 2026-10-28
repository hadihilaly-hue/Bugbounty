# Real-run readiness

Honest assessment of what's missing or weak before pointing this harness at a
**real, authorized** bug-bounty program. Everything below was run only against
local sandboxes (OWASP Juice Shop, DVWA, crAPI) and in-process fixtures, with
global `DRY_RUN` on. No real program has been added or touched.

## Where the validator stands (verified on combined `main`, post #12/#13/#14)
Full graded eval stood up and re-run **live** on current combined `main` via
`bugbounty eval-all` (Juice Shop `:3000`, DVWA `:4280`, crAPI `:8888` all up in
Docker), after the origin-scoped credential pinning (#11), the allowlist-aware
recon redirect fix (#13), and the handed-in-session wiring in the proof
harnesses (#14). These are the **verified integrated numbers**, recorded to the
store and the nightly report:

| target | precision | recall (all) | fp_rate | tp/fp/tn/fn | note |
|---|---|---|---|---|---|
| juiceshop | 1.00 | 0.83 | 0.00 | 10/0/6/2 | supported-only recall 1.00 |
| dvwa | 1.00 | 1.00 | 0.00 | 5/0/5/0 | CSRF + cookie session login |
| crapi | 1.00 | 0.80 | 0.00 | 4/0/2/1 | supported-only recall 1.00; includes the auth-gated handed-in-session BOLA |
| owasp-benchmark | – | – | – | answer key only | 2740 cases; needs Maven/Tomcat+crawler |

**No regression versus the #13 figures** (juiceshop 1.00/0.83/0.00, dvwa
1.00/1.00/0.00, crapi 1.00/0.75/0.00). Precision stays 1.00 and the
false-positive rate stays 0.00 on all three sandboxes. DVWA reports 5/0/5/0
rather than 4/0/4/0 because its adapter carries an extra graded case pair (the
timing-oracle blind-SQLi case), not because any verdict changed. crAPI moves
0.75 -> 0.80, explained below.

### The auth-gated case: the session handoff is now exercised in the graded eval
crAPI's adapter now captures **both** accounts' live bearer tokens at setup and
writes them to a separate gitignored `secrets/crapi-eval-session.yaml`
containing no passwords. A new graded case,
`crapi-bola-mechanic-report-session`, carries **no login spec**, so the IDOR
harness takes its *manual* handed-in-session path (origin-pinned, #11) rather
than scripting a login -- the same path a real OAuth/SSO/MFA/anti-bot target
would be tested through. It **CONFIRMS live**: owner B sees the victim marker,
an unauthenticated request does not, attacker A does, and A and B resolve to
distinct sessions. So the #14 handoff capability is no longer only proven on an
in-process sandbox; it is proven on a real vulnerable API in the graded eval.

**Does recall move up? Honestly: barely, and not for the reason it looks like.**
crAPI's all-cases recall rises 0.75 -> 0.80 purely because this adds one more
confirmed case. It re-proves the *same* mechanic-report BOLA through a
handed-in session -- it is **not** a newly reachable distinct bug. Juice Shop
(0.83) and DVWA (1.00) are unchanged. The reason is that every post-auth bug in
these local sandboxes is *already* reachable with a scriptable form/token login,
so the handoff cannot unlock anything new here. Its real recall value is on
targets whose login **cannot** be scripted (OAuth/SSO, MFA, CAPTCHA, device
fingerprinting), where today's alternative is no post-auth testing at all. Do
not read the 0.80 as the validator finding more bugs.

**Auth-gated stored XSS: attempted, not added -- honestly out of reach on this
target.** The intent was to confirm Juice Shop's `limit-stored-xss` case behind
a handed-in session. Probing the live sandbox showed the documented sink does
not fit the harness's generic stored mode: `lastLoginIp` is not readable from an
API (`/rest/user/whoami` returns `{}`), it reflects the **previous** login's IP
rather than the current request's, and it reaches the page inside the **JWT**,
which the Angular app renders from `localStorage`. Confirming it therefore needs
a two-login sequence whose resulting JWT is seeded into the browser -- a
target-specific dance the one-shot `inject -> render` stored mode does not
model. Forcing it would have produced a flaky or dishonest case, so Juice Shop's
stored XSS **remains a labelled coverage gap** (one of its two misses). The
auth-gated stored-XSS *capability* itself is proven in a real browser with a
seeded session in `tests/test_validator_xss_browser.py` and
`tests/test_validator_live_session.py`.

**Regression check (#11 credential pinning + #13 recon/scope, re-confirmed on
combined `main`):** both are intact and neither breaks a legitimate flow.
Credential pinning scopes a session to one origin (scheme+host+port); every eval
flow is same-origin, so none broke -- DVWA's CSRF+cookie login grades
1.00/1.00/0.00, and Juice Shop's and crAPI's two-account IDOR/BOLA cases still
CONFIRM, now including one driven by a **handed-in** session that is likewise
refused off its pinned origin. The recon allowlist/redirect behaviour still
refuses out-of-scope redirect destinations before contact, refuses `https ->
http` downgrades, and resolves links against the landing URL. Covered by
`tests/test_net_session.py::test_session_is_scoped_to_port_and_scheme`,
`::test_unconfigured_session_pins_to_first_origin_then_refuses_others`, and
`tests/test_recon_redirects.py` (in-scope cross-host hop followed, out-of-scope
refused via a real `Allowlist.decide`, scheme downgrade refused, links resolved
against the redirect destination). Full suite green: 156 passed.

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
**Post-auth testing is now wired into the proof harnesses (manual-handoff
case).** A session handed in via secrets (cookies / bearer / `local_storage`,
per account) is carried, origin-pinned, into BOTH the HTTP proof harnesses
(`httppoc` opt-in per account; `idor` for either account) AND the XSS render
navigation (cookies + localStorage seeded into the browser) — so IDOR/BOLA and
auth-gated stored XSS finally run post-auth without the harness attempting a
login. An expired/invalid handed-in session is surfaced loudly (UNCONFIRMED with
a clear reason), never run unauthenticated. **Proven end to end both in the graded eval and on a local
auth-gated sandbox.** In the eval: crAPI's `crapi-bola-mechanic-report-session`
proves a two-account BOLA on a real vulnerable API using handed-in bearer
sessions and no scripted login (CONFIRMED live). In-process
(`tests/test_validator_live_session.py`): two-account IDOR
over real HTTP with handed-in cookies → CONFIRMED, and an auth-gated stored XSS
rendered behind the session in a real browser → CONFIRMED; plus a unit test that
the handed-in session is refused off its pinned origin (the #11 fix holds for
handed-in sessions too).
**Still weak:** full OAuth/SSO redirect dances, WebAuthn/complex MFA, and
aggressive anti-bot (CAPTCHA / device fingerprinting) are not automated — that is
exactly what the manual handoff is for. `SessionManager` logins go through the
paced `net.build_client`, but the harness *request loops* (`idor`/`httppoc`)
still open their own un-paced httpx client for the proof requests themselves —
session-aware now, not yet pace-aware.

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

## If you added one real authorized program today, what breaks first (re-ranked)

**Is the login / post-auth gap closed? For the manual-handoff case, yes --
and it is now verified in the graded eval, not just in a test.** You log in
yourself in a real browser, hand in the live session via secrets, and the
validator carries it (origin-pinned) into the HTTP proof harnesses and the XSS
render — so IDOR/BOLA and auth-gated stored XSS run post-auth. A handed-in
two-account BOLA CONFIRMS live against crAPI in `bugbounty eval-all`. What is **not** closed: *automated* login for
OAuth/SSO/MFA/anti-bot (by design — hand in a session instead), and keeping that
session alive. So the former #1 ("login blocks all post-auth") drops; the
friction and the freshness/writes of the handed-in session move up.

1. **Recall / proof coverage.** Still the biggest gap. Even fully authenticated,
   the validator only proves SQLi/auth-HTTP, two-account IDOR/BOLA, reflected/
   DOM **and now auth-gated stored** XSS, time-based blind SQLi (timing oracle),
   and missing-auth/exposure. CSRF, live SSRF, JWT/alg-confusion, and
   business-logic bugs still come back UNCONFIRMED → a human-triage backlog and a
   confirmed-recall well below the sandbox figures.
2. **Rate limiting / WAF reality + unpaced harness requests.** The fixed 1 req/s
   + 429 backoff is polite but naive against a real WAF/CDN that may block,
   tarpit, or fingerprint; and the `idor`/`httppoc` proof **request loops** still
   open their own **unpaced** httpx client (session-aware now, but not routed
   through `net.build_client`), so those requests bypass per-host pacing —
   risking tripped protection mid-proof. Wire the harness request path through
   `net.build_client` next.
3. **Session lifecycle for post-auth: capture friction, expiry, and writes.** The
   manual handoff works but is manual: a human must capture a browser session per
   account, and it goes stale — we now surface an expired handed-in session
   clearly (good), but testing halts until you paste a fresh one, and there's no
   refresh. Write-based post-auth tests (CSRF, IDOR-on-write, password reset)
   also need per-request CSRF-token handling the proof harnesses don't do yet.

## Recommendation
The two HIGH gaps (auth/session, rate limiting) and the recon/scope redirect fix
are closed and verified on current combined `main` (post #12/#13/#14) with the
sandboxes actually stood up: precision 1.00 and fp_rate 0.00 across all three,
and the session handoff exercised by a graded auth-gated case. Before a real program: (1) the validator
proof harnesses are now **session-aware** (handed-in session carried in,
origin-pinned) — the remaining half is routing their proof *request loops*
through `net.build_client` so they are **paced** too; (2) keep `DRY_RUN` on for a first
**supervised** pass (recon + static only), clearing the gate only for a single
known endpoint you watch live; (3) treat unproven-class findings as manual
triage, not misses; (4) use the manual handed-in-session path for
OAuth/SSO/MFA/anti-bot targets; (5) add evidence redaction before storing live
HTTP bodies.
