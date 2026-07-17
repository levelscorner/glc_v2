"""Per-client rate limit on the public HTTP data plane (finding C5).

The migration put `/v1/chat`, `/v1/embed`, `/v1/vision`, `/v1/speak`, and
`/v1/transcribe` on a public URL with no request throttling. That is a DoS
and denial-of-wallet vector: an attacker floods the endpoints and burns the
account's provider budget. The existing per-(channel, user) limiter only
covers the WS/webhook channel path, not anonymous HTTP callers.

This middleware adds a sliding 60-second window per client IP. The cap is
``GLC_DATAPLANE_RPM`` (default 60; set higher/lower on the deployment; 0
disables). Exceeding it returns 429 with ``Retry-After``.

Invariant 8 (Section 4): every run must have hard limits on time, tokens,
tool calls, and cost. This is the request-rate limit; token/cost budgets ride
on the cost ledger (`/v1/cost/by_agent`) and are a documented follow-up.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_LIMITED_PREFIXES = (
    "/v1/chat",
    "/v1/embed",
    "/v1/vision",
    "/v1/speak",
    "/v1/transcribe",
)


def _rpm() -> int:
    try:
        return int(os.getenv("GLC_DATAPLANE_RPM", "60"))
    except ValueError:
        return 60


def _is_limited(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in _LIMITED_PREFIXES)


class DataPlaneRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        if _is_limited(request.url.path):
            rpm = _rpm()
            if rpm > 0:
                ip = request.client.host if request.client else "unknown"
                now = time.time()
                horizon = now - 60.0
                with self._lock:
                    dq = self._hits.setdefault(ip, deque())
                    while dq and dq[0] < horizon:
                        dq.popleft()
                    if len(dq) >= rpm:
                        retry = max(1, int(60 - (now - dq[0])))
                        return JSONResponse(
                            {"detail": "rate limit exceeded"},
                            status_code=429,
                            headers={"Retry-After": str(retry)},
                        )
                    dq.append(now)
        return await call_next(request)
