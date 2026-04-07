from typing import cast
from flask import Flask
from authlib.integrations.flask_client import OAuth, FlaskOAuth2App
from ..config import settings

_oauth: OAuth | None = None


def _register(oauth: OAuth) -> None:
    """Register (or re-register) the OIDC client with current settings."""
    oauth.register(
        name="entra",
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=settings.OIDC_METADATA_URL,
        client_kwargs={"scope": settings.OIDC_SCOPES},
    )


def init_oauth(app: Flask) -> None:
    global _oauth
    _oauth = OAuth(app)
    _register(_oauth)


def reregister_oidc() -> None:
    """Re-register the OIDC client after runtime settings change."""
    if _oauth is None:
        raise RuntimeError("OAuth not initialized; call init_oauth(app) first.")
    # Clear cached client so a fresh one is created with new settings
    if hasattr(_oauth, "_clients"):
        _oauth._clients.pop("entra", None)
    if hasattr(_oauth, "_registry"):
        _oauth._registry.pop("entra", None)
    _register(_oauth)


def get_client() -> FlaskOAuth2App:
    if _oauth is None:
        raise RuntimeError("OAuth not initialized; call init_oauth(app) first.")
    client = _oauth.create_client("entra")
    if client is None:
        raise RuntimeError("OIDC client 'entra' is not registered")
    return cast(FlaskOAuth2App, client)