"""
Modal deployment wrapper for glc_v1  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
image = (
    modal.Image.debian_slim(python_version="3.11")
    # A5 fix: pin every dependency to the exact version resolved in uv.lock
    # instead of ">=" ranges, so a redeploy cannot silently pull a newer
    # (possibly poisoned) release — the supply-chain-drift the migration left
    # open. (Pinning the base image by digest is the further hardening step.)
    .pip_install(
        "fastapi==0.137.1",
        "uvicorn[standard]==0.49.0",
        "httpx==0.28.1",
        "python-dotenv==1.2.2",
        "pydantic==2.13.4",
        "jsonschema==4.26.0",
        "pyyaml==6.0.3",
        "websockets==16.0",
        "twilio==9.10.9",
    )
    # Turn the hardening on for the public deployment: require the gateway
    # bearer token (A1), disable Swagger/OpenAPI (A2), and cap the data-plane
    # request rate (C5). GLC_GATEWAY_TOKEN itself arrives via the Secret below,
    # so it is never baked into the image.
    .env(
        {
            "GLC_CONFIG_DIR": "/data/glc",
            "GLC_REQUIRE_AUTH": "1",
            "GLC_DISABLE_DOCS": "1",
            "GLC_DATAPLANE_RPM": "60",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")

# The gateway bearer token (A1) lives in its own Secret, separate from the
# provider keys — a distinct credential per surface.
auth_secret = modal.Secret.from_name("glc-gateway-auth")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, auth_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    return web
