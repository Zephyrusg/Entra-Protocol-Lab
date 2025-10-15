from flask import Blueprint, session, redirect, url_for
from flask.typing import ResponseReturnValue
import secrets
from ..utils.crypto import pkce_challenge
from ..utils.html import page, pretty_json
from ..config import settings
from .client import get_client

bp = Blueprint("oidc", __name__)

@bp.get("/login")
def login() -> ResponseReturnValue:
    verifier = secrets.token_urlsafe(64)
    session["oidc_code_verifier"] = verifier
    challenge = pkce_challenge(verifier)
    nonce = secrets.token_urlsafe(32)
    session["oidc_nonce"] = nonce
    resp = get_client().authorize_redirect(
        redirect_uri=settings.OIDC_REDIRECT_URI,
        code_challenge=challenge, code_challenge_method="S256", nonce=nonce
    )
    return resp  # FlaskOAuth2App returns a valid Response

@bp.get("/callback")
def callback() -> ResponseReturnValue:
    verifier = session.pop("oidc_code_verifier", None)
    nonce = session.pop("oidc_nonce", None)
    if not verifier or not nonce:
        return page("OIDC Error", "<p>Missing PKCE verifier or nonce in session.</p>")
    token = get_client().authorize_access_token(code_verifier=verifier)
    if not token:
        return page("OIDC Error", "<p>Token exchange failed.</p>")
    claims = get_client().parse_id_token(token, nonce=nonce)
    session["oidc"] = {"token": token, "claims": claims}
    return redirect(url_for("oidc.user"))

@bp.get("/user")
def user() -> ResponseReturnValue:
    data = session.get("oidc")
    if not data:
        return page("OIDC User", '<p>Not signed in. <a href="/oidc/login">Login</a></p>')
    body = "<h2>ID Token Claims</h2><pre>" + pretty_json(data["claims"]) + "</pre>"
    body += "<h2>Raw Token Set</h2><pre>" + pretty_json(data["token"]) + "</pre>"
    body += "<p><a href='/oidc/logout'>OIDC Logout</a></p>"
    return page("OIDC User", body)

@bp.get("/logout")
def logout() -> ResponseReturnValue:
    session.pop("oidc", None)
    end_session = f"https://login.microsoftonline.com/{settings.TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri={settings.BASE_URL}"
    return redirect(end_session)