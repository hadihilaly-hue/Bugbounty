# Validator harness notes

What each proof harness treats as **proof**, and — honestly — the ways it can
still false-positive (FP: confirm a non-bug) or false-negative (FN: reject or
fail to confirm a real bug). The validator is adversarial by construction: a
candidate is only ever `CONFIRMED` when a harness executes a proof whose oracle
positively demonstrates the bug. Everything else is `REJECTED` (actively
disproven) or `UNCONFIRMED` (could not be proven). Errors never confirm.

Two guarantees hold across all classes:

- **Dry-run gating** (`engine.py` + `config.py`): a harness that sends an
  active payload runs only when global `DRY_RUN` is off *and* the target's own
  `dry_run` is off *and* the kill switch is off. Otherwise → `UNCONFIRMED`.
- **Proof-integrity guard** (`engine.py`): a `CONFIRMED` result that carries
  neither evidence nor a PoC is downgraded to `UNCONFIRMED`. A harness bug
  cannot confirm a finding on an empty claim.

---

## XSS (`harnesses/xss.py`)

**Proof:** a real headless browser loads the payload and a JS **dialog** or
**console** message fires whose text contains a per-run high-entropy **nonce**.
Because the site cannot already know the nonce, an attributed hit proves *our*
injected script executed. Modes: `reflected` / `dom` (navigate one URL) and
`stored` (inject via HTTP, then navigate to the view URL). Reflection of the
payload as inert DOM text is captured as evidence and **rejected**, never
confirmed. A screenshot is always kept.

Attribution is mandatory: the candidate must either use a `{NONCE}` template
(harness controls the value) or declare `expect_marker` (the exact string its
payload emits). No attribution → `UNCONFIRMED`, by design.

- **Can still FP if:** the application itself reflects the nonce into a *new*
  script context that executes it independently of the injection (rare, but the
  nonce alone doesn't prove *which* sink ran). A payload that triggers a dialog
  whose text an attacker fully controls is genuine XSS, so this is mostly
  theoretical.
**Proven against a real browser** (not just the decision core): the reflected,
DOM, and stored paths all execute end to end in a headless Chromium against a
local target, and a reflected-but-escaped page is correctly rejected — see
`tests/test_validator_xss_browser.py` (run on demand with `-m browser`; skipped
cleanly where no browser is launchable).

- **Can still FP if:** the application itself reflects the nonce into a *new*
  script context that executes it independently of the injection (rare; the
  nonce alone doesn't prove *which* sink ran).
- **Can still FN if:** the XSS needs user interaction (a click, focus, specific
  route state) the harness doesn't perform; executes only after the fixed
  ~1.5s settle wait; requires a framework sink the single navigation doesn't
  reach; or is blocked by a CSP in headless mode that differs from a victim's
  real browser. Stored XSS whose injection needs auth/CSRF the candidate didn't
  supply fails at the inject step → `UNCONFIRMED`.
- **Unproven / known gap:** the harness browser navigates the view URL with **no
  session**, so a stored-XSS sink that renders only on an *authenticated* page
  (e.g. Juice Shop's True-Client-IP → last-login-ip) cannot be confirmed yet —
  the stored *mechanism* is proven, carrying auth cookies/JWT into the render
  navigation is future work.
- **Not covered:** mutation/blind XSS with no observable dialog or console
  marker; exfiltration-only payloads. These need an OOB channel (see SSRF).

## IDOR / broken access control (`harnesses/idor.py`)

**Proof:** a four-part argument, every request logged (identity, method, URL,
status):

1. A and B log in; their session tokens **must differ** (two real accounts).
2. **Owner baseline** — B reads B's object and sees the marker (proves the
   marker identifies B's private object and the endpoint is live). If not →
   `UNCONFIRMED` (broken setup, not a pass).
3. **Public baseline** — an *unauthenticated* client reads the object. If it
   sees the marker, the object is **public/shared → REJECTED** (this is the
   guard against the classic shared-object false positive).
4. **Attacker** — A reads B's object. `CONFIRMED` only when A succeeds
   (`<400`) and sees the marker, owner could, and the public could not.

- **Can still FP if:** the `victim_marker` is low-entropy or not actually unique
  to B (e.g. a shared product name, a common field value) — A could legitimately
  possess the same string. **Use a high-entropy marker unique to B's object.**
  Also: an object shared with A specifically (a legitimate grant) looks
  identical to an IDOR from the outside; the harness can't know the intended
  ACL. And an object that's public only to *authenticated* users would pass the
  anonymous baseline yet not be a real cross-tenant leak.
- **Can still FN if:** the resource needs more than a bearer token (CSRF header,
  cookie, step-up auth) the candidate didn't model; the object id must be
  discovered dynamically; access is state-dependent (time/feature-flag); or the
  marker is present but transformed (re-encoded, truncated) in A's response.
- **Note:** only read-IDOR is modeled. Write/delete-based BAC (A mutating B's
  object) is out of scope here.

## HTTP PoC — SSRF / auth / injection (`harnesses/httppoc.py`)

**Proof:** an ordered request sequence is replayed (with token threading —
capture a value from one response, substitute `{{name}}` into later requests),
then a **strict oracle** must match:

- `jwt` — the located value is a *structurally valid* JWT (three base64url
  segments, decodable JSON header+payload, real `alg`). This is the "a real auth
  token was returned" oracle. **Not a signature check** — we can't verify the
  server's key — so it proves *a well-formed token was issued*, not that it's
  unexpired or server-trusted.
- `oob` — an out-of-band callback fired. The harness mints a unique token,
  embeds it (`{{oob}}`), and asks an injected collaborator whether *that* token
  was seen. No collaborator configured → `UNCONFIRMED` (we never assume a hit).
- `timing` — for **blind/time-based** injection with no visible output: a
  baseline request and an injected (`SLEEP(n)`) request are both timed, and the
  bug is confirmed only when the injected response's median is slower than the
  baseline's by at least `min_delta_seconds`, is itself at least that floor, and
  (with several samples) every injected sample beats every baseline sample.
  Deliberately strict so normal latency jitter cannot confirm. Pair with a large
  sleep and multiple samples for confidence.
- `contains` / `regex` / `status` — cheap checks. A short `contains` value FPs
  easily; prefer `jwt`/`oob`/`timing`/anchored `regex`. The emitted PoC is a
  rerunnable bash script (captures via `curl | python3`, threaded as shell vars).

- **Can still FP if:** a `contains`/`status` oracle is weak (the matched string
  also appears on benign responses); a `regex` is unanchored; or, for `jwt`, the
  endpoint returns a structurally valid but *inert/expired/non-privileged* token
  that doesn't actually grant access. For injection, a reflected error string
  can satisfy a loose `contains` without the query executing — use `jwt` for
  auth bypass or a differential oracle instead.
- **Can still FP if:** a `contains`/`status` oracle is weak; a `timing` oracle is
  used with too small a `min_delta_seconds` on a high-variance target, or a
  single sample catches a one-off slow response (use a large sleep + several
  samples). 
- **Can still FN if:** the real OOB collaborator is unreachable or slow (the
  callback lands after we check → `UNCONFIRMED`); a time-based bug's delay is
  smaller than the (strict) threshold; the capture path shape differs from what
  the candidate declared (→ `UNCONFIRMED`); or success shows only in a response
  header/cookie the oracle isn't pointed at.
- **Proven:** the `timing` oracle is unit-tested for the jitter-rejection
  boundaries and exercised end to end through a delaying transport; it is wired
  as a **live** case on the DVWA eval target (MySQL `SLEEP()` works there).
- **Not covered:** boolean-based blind (only time-based has an oracle),
  second-order injection across requests the sequence doesn't include, and
  signature/trust verification of returned tokens.

---

## What is proven, and how

Three layers of test, strongest first:

1. **Real headless browser (XSS), local target** — `test_validator_xss_browser.py`
   runs the actual `XssHarness.run` against a stdlib HTTP server and confirms
   nonce-attributed execution for **reflected, DOM, and stored** XSS, and
   **rejects** a reflected-but-escaped page. Runs wherever a Chromium is
   launchable (honors `BB_CHROMIUM_EXECUTABLE`); **skips cleanly** where none is
   (e.g. CI). Run on demand with `pytest -m browser`.
2. **End-to-end I/O over `httpx.MockTransport`** (no network) — IDOR's full
   two-account + baselines flow, HTTP PoC token threading, the `jwt`/`oob`
   oracles, and the `timing` oracle through a delaying transport.
3. **Pure decision cores** — oracles, nonce attribution, capture/substitution,
   and the `timing` jitter-rejection boundaries, as deterministic unit tests.

Each class has a true-positive **and** a hard-negative (patched / benign /
public / escaped / non-token / no-callback → `REJECTED` or `UNCONFIRMED`), so
the false-positive direction is measured, not just recall. `DRY_RUN` stays on;
harnesses are driven directly in tests (the engine's dry-run gate is tested
separately).

## Proven against a real target vs still decision-logic-only

- **XSS execution (reflected / DOM / stored):** proven in a real browser against
  a local target. *Not* decision-logic-only anymore.
- **Timing oracle (blind/time-based SQLi):** jitter boundaries unit-tested;
  end-to-end through a delaying transport; wired as a **live** DVWA case
  (run `bugbounty` eval against a local DVWA to execute it).
- **IDOR, `jwt`, `oob`:** decision + I/O proven over mock transports; a full live
  run still needs the respective sandbox (and, for `oob`, a real collaborator).

## Benchmark / eval recall (Juice Shop)

The two eval cases that were previously **recall misses for a validator-side
reason** are now wired to the new capabilities, but remain `limitation` on Juice
Shop for **target-side** reasons, stated honestly in each case's note:

- *Blind/time-based SQLi* — the `timing` oracle now exists, but Juice Shop runs
  **SQLite, which has no `SLEEP()`**, so no delay is inducible on this target.
  The oracle's live proof is on **DVWA** (MySQL) instead.
- *Stored XSS* — the stored harness now exists and is browser-proven, but Juice
  Shop's documented sink renders on an **authenticated** page the harness
  browser does not yet carry a session into.

So the **validator-side** gaps are closed and proven; the residual Juice Shop
misses are target/auth properties, not missing harness capability. The eval
numbers on Juice Shop are unchanged until those target-side blockers are
addressed; re-run the eval against a local Juice Shop / DVWA (dry-run gate
cleared for the local sandbox only) to measure live.
