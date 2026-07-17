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
