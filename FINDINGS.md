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
