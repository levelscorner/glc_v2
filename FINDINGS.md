# Session 12 — Part 1 findings ledger

Migrated `glc_v2` to Modal (Section 6, Move 1) and hardened it. Deployment is
scale-to-zero on mock keys. For each finding below: the invariant it breaks
(Section 4), how it was reproduced, and the fix.

**Deployment:** `modal deploy modal_app.py` → public URL, `curl <url>/healthz`
returns `{"ok": true}`. `GLC_REQUIRE_AUTH=1`, `GLC_DISABLE_DOCS=1`, and the
`GLC_GATEWAY_TOKEN` are set on the deployment via the Modal Secret.

The eight invariants (Section 4), referenced by number below:
1. Adapters must never see provider API keys.
2. Every action must be checked against the actual user, tenant, and final arguments.
3. External content must always be treated as data, never as instructions.
4. A credential must work only for one specific tool call.
5. Each tenant must have separate memory; every stored fact records its source.
6. Dangerous/high-impact actions must be approved with their final parameters.
7. Components must not be able to edit or delete their own audit logs.
8. Every run must have hard limits on time, tokens, tool calls, and cost.

---

## A1 — Public data plane, no auth  ·  invariant 2  ·  CRITICAL

**Reproduce (public URL):** `curl -X POST <url>/v1/chat -d '{...}'` returns a
provider error (`502/503`), not `401` — any anonymous caller reaches the data
plane (`/v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`, `/transcribe`).

**Fix:** `glc/security/gateway_auth.py` — `GatewayAuthMiddleware` requires
`Authorization: Bearer <GLC_GATEWAY_TOKEN>` on all data-plane + info endpoints
when `GLC_REQUIRE_AUTH=1`. Constant-time compare, fails closed on an empty
expected token. The gateway token is a *separate* credential from the
control-plane install token, delivered via the Modal Secret (never in the image).
The control plane (`/v1/control/*`, own install-token auth) and channel webhooks
(`/v1/channels/*`, per-adapter auth) are exempt; `/healthz` and `/` stay open.

**Verify:** gated endpoint → `401` with no or wrong token, `200` with the token;
`/healthz` → `200`.

## A2 — Unauthenticated info disclosure  ·  invariant 2  ·  HIGH

**Reproduce:** `/v1/status`, `/v1/providers`, `/v1/capabilities`,
`/v1/cost/by_agent`, `/v1/calls`, plus `/docs` and `/openapi.json` all return
`200` unauth, leaking provider order, models, rate limits, usage, and the full
route map.

**Fix:** same middleware gates the info endpoints; `main.py` disables the
OpenAPI schema and Swagger/ReDoc explorers (`docs_url/redoc_url/openapi_url =
None`) when `GLC_DISABLE_DOCS=1` on the deployment.

**Verify:** info endpoints → `401` without token; `/docs` and `/openapi.json`
→ `404` on the deployment.

## Leak 9 / C2 — Cross-channel envelope spoofing  ·  invariant 3  ·  HIGH

**Reproduce:** connect to `WS /v1/channels/telegram` (with the install token)
and send a `ChannelMessage` whose `channel="discord"`. Pre-fix the gateway
processes it as Discord — the Telegram adapter has impersonated another channel.

**Fix:** `glc/routes/channels.py` — after validating the envelope, reject any
message whose `env.channel` differs from the route `name`: record a
`channel_spoof` audit event, send a `channel mismatch` error, and close the
socket (`WS_1008_POLICY_VIOLATION`). The same check is applied on the webhook
POST path (`msg.channel != name` → `400`).

**Verify:** matched `telegram` envelope proceeds; `discord`-on-`telegram` →
rejected with "channel mismatch: envelope declares 'discord' on route
'telegram'", socket closed, no echo. 249/249 tests still pass.

## C1 — SSRF via `/v1/vision` image resolver  ·  invariant 2  ·  HIGH

**Reproduce:** send a chat/vision request with an `image_url` block pointing
at an internal address (`http://169.254.169.254/…`, `http://127.0.0.1:8111/…`,
a private IP). Pre-fix `_resolve_image_urls` fetches it with
`follow_redirects=True` and no allowlist — the gateway proxies internal
resources, and a public URL can 302 into the private network.

**Fix:** `glc/security/ssrf.py` — `check_url_allowed()` rejects non-http(s)
schemes and any host that resolves to a private/loopback/link-local/
multicast/reserved/unspecified address (v4+v6), with an optional
`GLC_IMAGE_URL_ALLOWLIST`. `_resolve_image_urls` now disables auto-redirects
and re-validates every hop (max 5). Residual: DNS-rebinding (pin-IP) noted as
follow-up.

**Verify:** metadata IP, `127.0.0.1:8111`, `10/8`, `192.168/16`, `::1`,
`ftp://`, `file://` all blocked; public hosts allowed; allowlist enforced.
249/249 tests pass.

## C4 — Verbose upstream errors leaked to client  ·  invariant 2  ·  MEDIUM

**Reproduce:** a failing `/v1/chat` or `/v1/embed` returns the raw provider
exception, the provider name, and the full `all_attempts` list in the HTTP
error body — free internal detail for an attacker.

**Fix:** `glc/routes/chat.py` — client-facing raises now return generic
messages ("upstream provider error", "all upstream providers unavailable",
"upstream embed error"); full detail (provider, exception) goes to the
`glc.chat` logger and the cost-ledger `error` column, not the client.

**Verify:** 249/249 tests pass (no test depended on the leaked strings);
error bodies no longer echo provider internals.

## C5 — No rate limit / budget on the public data plane  ·  invariant 8  ·  HIGH

**Reproduce:** the existing limiter only covers the WS/webhook channel path;
`/v1/chat`, `/v1/embed`, `/v1/vision`, `/v1/speak`, `/v1/transcribe` accept
unbounded requests from any IP — DoS and denial-of-wallet on a shared account.

**Fix:** `glc/security/http_ratelimit.py` — `DataPlaneRateLimitMiddleware`, a
per-client-IP sliding-60s-window limiter (`GLC_DATAPLANE_RPM`, default 60),
added ahead of auth so floods are throttled first; returns 429 + `Retry-After`.
Token/cost budgets ride on the cost ledger and are a documented follow-up.

**Verify:** cap 3 → `[400,400,400,429,429]` on `/v1/embed`; `/healthz`
unthrottled; 249/249 tests pass.

## C3 — WS install token in the query string  ·  invariant 4  ·  MEDIUM

**Reproduce:** `WS /v1/channels/{name}?token=<install_token>` — the token lands
in access logs, proxy logs, and browser history.

**Fix:** `glc/routes/channels.py` — accept the token only from the
`Authorization: Bearer` header; the `?token=` fallback is off unless
`GLC_ALLOW_WS_QUERY_TOKEN=1`. Comparison is constant-time (`hmac.compare_digest`).

**Verify:** header auth still connects; query-token rejected by default; existing
control-plane/WS tests (header-based) still pass.

## Leak 2 / A6 — Audit log tamperable at the OS layer  ·  invariant 7  ·  HIGH

**Reproduce:** the app layer exposes only `append()`, but the SQLite file is
writable, so in-process code runs
`sqlite3.connect(path).execute("DELETE FROM audit_log")` and erases history.

**Fix:** `glc/audit/` — every row now carries `prev_hash` and
`row_hash = sha256(prev_hash ‖ canonical row)`, chained from a genesis value.
`verify_chain()` recomputes the chain and returns the first broken id, so a
deleted, edited, or truncated log is detectable even when the raw file is
tampered with. Appends are serialized with a lock (intra-process); a single
cross-container append-only writer is the deeper A6 fix (documented).

**Verify:** 5 clean appends → chain OK; `DELETE id=3` → detected (first_bad=4);
`UPDATE id=1` → detected (first_bad=1). 249/249 tests pass.

## In-process leaks 1, 3, 4, 5, 8, 10 — shared process = shared blast radius

These all stem from every adapter running in one process with one shared
environment. The **complete** fix for 1/3/4/5/8 is component separation:
each adapter in its own Modal Sandbox with its own Secret, scoped
credentials per tool call, a separate PID namespace, and the policy engine
in its own process. That is the deployment-layer rework (A3/A4 + capstone
scope). What is closeable *in code* now:

- **Leak 10 — cost-ledger poisoning ✅ CLOSED (invariant 8).** `glc/db.py`
  `log_call` now clamps every caller-supplied count (`input_tokens`, …) to a
  sane ceiling and logs out-of-range values. Verified: `input_tokens=999_999_999`
  → stored `10_000_000`, warning logged.
- **Leak 3 — force_pair_owner escalation ⚠️ DETECTION added (invariant 7).**
  `glc/security/pairing.py` now writes a `force_pair_owner` event to the
  tamper-evident audit log on every call, so a silent in-process escalation is
  visible after the fact. Full close = component separation. Verified: attacker
  escalation produces an audit row.
- **Leaks 1, 4, 5, 8 — DOCUMENTED, deployment-layer.** Shared env keys (1),
  in-process install-token read (4), policy monkey-patch (5), and
  `os.kill(getpid)` (8) cannot be closed from inside a single shared process;
  they require per-adapter containers / Secrets / PID namespaces. Tracked for
  the A3/A4 deployment fixes and the capstone.

## A3–A6 — deployment layer (`modal_app.py`)

The hardening is now switched on for the public deployment, and the image is
made reproducible:

- **A1/A2/C5 enforced live.** `modal_app.py` sets `GLC_REQUIRE_AUTH=1`,
  `GLC_DISABLE_DOCS=1`, `GLC_DATAPLANE_RPM=60`. Verified on the public URL:
  `/v1/chat` and `/v1/status` → **401** without the token, `200`/`502` with it;
  `/docs` and `/openapi.json` → **404**. (Pre-fix all were open.)
- **A4 (one Secret) — partially addressed.** The gateway bearer token lives in
  its own Secret (`glc-gateway-auth`), separate from the provider keys
  (`glc-llm-keys`) — a distinct credential per surface. Full per-adapter secret
  isolation is component separation (documented).
- **A5 (non-reproducible image) — CLOSED (build side).** Every dependency is
  pinned to its exact `uv.lock` version (no more `>=` drift). Pinning the base
  image by digest is the remaining step.
- **A6 (audit db on Volume + autoscale).** Tamper-evidence is provided by the
  leak-2 hash chain; the concurrent-writer corruption needs a single
  append-only writer (deeper fix, documented).
- **A3 (no egress wall).** Requires running adapters as Modal Sandboxes with
  `outbound_domain_allowlist` — component separation, documented.

Public deployment: `https://rabhinavcs--glc-v1-gateway-fastapi-app.modal.run`
(scale-to-zero, mock keys only).
