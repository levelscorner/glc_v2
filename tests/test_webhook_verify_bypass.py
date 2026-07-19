"""Reproduction for the webhook verify-token bypass (Session 12, Part 2).

GET /v1/channels/{name}/webhook authenticates the Meta-style subscription
handshake by comparing the caller's `hub.verify_token` against the env var
`{NAME}_VERIFY_TOKEN`. When that env var is unset — the default on a fresh
deploy — the expected value is the empty string, and
`hmac.compare_digest(token, "")` is True for an empty presented token. Any
caller can then complete the handshake and register a webhook for that
channel.

Invariant broken: #2 (every action must be checked against the actual user
/ tenant). An empty configured secret means the check passes for everyone.

Run: `uv run pytest tests/test_webhook_verify_bypass.py -v`
"""

from __future__ import annotations

import os

from starlette.testclient import TestClient

from glc.main import app


def _clear_verify_tokens(monkeypatch) -> None:
    for k in list(os.environ):
        if k.endswith("_VERIFY_TOKEN"):
            monkeypatch.delenv(k, raising=False)


def test_unset_token_rejects_empty_handshake(monkeypatch):
    """With no {NAME}_VERIFY_TOKEN configured, the handshake must fail closed.

    On the unpatched gateway this returns 200 with the challenge echoed back
    (the bypass). With the fix it returns 403.
    """
    _clear_verify_tokens(monkeypatch)
    with TestClient(app) as c:
        r = c.get(
            "/v1/channels/telegram/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "PWNED"},
        )
    assert r.status_code == 403, f"webhook verify bypass: got {r.status_code} body={r.text!r}"


def test_configured_token_still_works(monkeypatch):
    """A correctly configured token still verifies; a wrong one is rejected."""
    _clear_verify_tokens(monkeypatch)
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cret")
    with TestClient(app) as c:
        ok = c.get(
            "/v1/channels/telegram/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "s3cret", "hub.challenge": "CHAL"},
        )
        bad = c.get(
            "/v1/channels/telegram/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "CHAL"},
        )
    assert ok.status_code == 200 and ok.text == "CHAL"
    assert bad.status_code == 403
