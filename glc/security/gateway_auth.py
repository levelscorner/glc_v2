"""Gateway authentication front door (Session 12 hardening).

Closes findings **A1** (public data plane, no auth) and **A2**
(unauthenticated info disclosure). The migration to Modal moved the
gateway from ``localhost:8111`` — reachable only from the operator's own
machine — onto a public internet URL, and it added no front door. Every
data-plane and status endpoint answered to any anonymous caller.

Invariant restored (Section 4): *"Every action must be checked against the
actual user, tenant, and final arguments."* A public URL with no auth lets
anyone act as the gateway; requiring a bearer token at the edge
re-establishes that check for the whole data plane.

Design notes:
- Enforcement is opt-in via ``GLC_REQUIRE_AUTH=1`` so local dev on
  loopback stays frictionless; the Modal deployment sets it to ``1``.
- The token is delivered as ``GLC_GATEWAY_TOKEN`` via the Modal Secret,
  never baked into the image, and is *separate* from the control-plane
  install token (distinct credential per surface).
- The control plane (``/v1/control/*``) keeps its own install-token auth,
  and channel webhooks (``/v1/channels/*``) authenticate per adapter, so
  both are exempt here rather than double-gated.
- ``/healthz`` and ``/`` stay open for liveness checks.
"""

from __future__ import annotations

import hmac
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Data-plane + info endpoints named in findings A1 and A2. Prefix match, so
# "/v1/chat" also covers "/v1/chat/batch".
_GATED_PREFIXES = (
    "/v1/chat",
    "/v1/embed",
    "/v1/embedders",
    "/v1/vision",
    "/v1/speak",
    "/v1/transcribe",
    "/v1/status",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/routers",
    "/v1/cost",
    "/v1/calls",
)


def auth_required() -> bool:
    return os.getenv("GLC_REQUIRE_AUTH") == "1"


def _expected_token() -> str:
    return os.getenv("GLC_GATEWAY_TOKEN", "")


def _is_gated(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in _GATED_PREFIXES)


class GatewayAuthMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <GLC_GATEWAY_TOKEN>`` on gated routes."""

    async def dispatch(self, request: Request, call_next):
        if auth_required() and _is_gated(request.url.path):
            expected = _expected_token()
            header = request.headers.get("authorization", "")
            presented = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
            # Constant-time compare; empty expected token also fails closed.
            if not expected or not presented or not hmac.compare_digest(presented, expected):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)
