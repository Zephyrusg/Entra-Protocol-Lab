from typing import cast
from flask import Flask
from authlib.integrations.flask_client import OAuth, FlaskOAuth2App
from ..config import settings

_oauth: OAuth | None = None

def init_oauth(app: Flask) -> None:
    global _oauth
    _oauth = OAuth(app)
    _oauth.register(
        name="entra",
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=f"https://login.microsoftonline.com/{settings.TENANT_ID}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )

def get_client() -> FlaskOAuth2App:
    if _oauth is None:
        raise RuntimeError("OAuth not initialized; call init_oauth(app) first.")
    client = _oauth.create_client("entra")
    if client is None:
        raise RuntimeError("OIDC client 'entra' is not registered")
    return cast(FlaskOAuth2App, client)