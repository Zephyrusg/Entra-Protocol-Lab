import secrets, os
from flask import Blueprint, session, redirect, url_for, request, make_response
from flask.typing import ResponseReturnValue
from authlib.integrations.base_client.errors import OAuthError
from .client import get_client
from ..utils.crypto import pkce_challenge
from ..utils.html import page, pretty_json, redact
from ..config import settings
from urllib.parse import urlencode

bp = Blueprint("oidc", __name__)

@bp.get("/login")
def login() -> ResponseReturnValue:
    # Allow ?next=/some/path to redirect back after login
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/"):
        session["login_next"] = next_url
        session.modified = True

    verifier = secrets.token_urlsafe(64)
    session["oidc_code_verifier"] = verifier
    challenge = pkce_challenge(verifier)
    nonce = secrets.token_urlsafe(32)
    session["oidc_nonce"] = nonce

    resp = get_client().authorize_redirect(
        redirect_uri=settings.OIDC_REDIRECT_URI,
        code_challenge=challenge,
        code_challenge_method="S256",
        nonce=nonce,
    )
    # Set cookie as backup — session may not survive the IdP round-trip
    if next_url and next_url.startswith("/"):
        resp.set_cookie("login_next", next_url, max_age=600, httponly=True, samesite="Lax")
    return resp

@bp.get("/callback")
def callback() -> ResponseReturnValue:
    verifier = session.pop("oidc_code_verifier", None)
    nonce = session.pop("oidc_nonce", None)
    if not verifier or not nonce:
        # Session may not have been established on the very first login
        # attempt (cookie race). Retry once automatically.
        retries = session.get("oidc_retry", 0)
        if retries < 1:
            session["oidc_retry"] = retries + 1
            return redirect(url_for("oidc.login", **request.args))
        session.pop("oidc_retry", None)
        return page("OIDC Error", "<p>Missing PKCE verifier or nonce in session. "
                     "This usually means the session cookie was lost during the login redirect. "
                     "Try <a href='/oidc/login'>logging in again</a>.</p>")

    try:
        token = get_client().authorize_access_token(code_verifier=verifier)
    except OAuthError as exc:
        desc = str(exc.description or exc)
        if "AADSTS7000215" in desc or "invalid_client" in str(exc.error or ""):
            return page("OIDC Error — Invalid Client Secret",
                        "<p><b>The client secret is invalid or expired.</b></p>"
                        "<p>Go to <b>Entra → App Registrations → [your app] → Certificates &amp; secrets</b>, "
                        "create a new secret, and update <code>OIDC_CLIENT_SECRET</code> in your <code>.env</code> file.</p>"
                        "<p style='margin-top:12px;color:#6b7280;font-size:13px'>Make sure you copy the secret <b>Value</b>, not the Secret ID.</p>")
        return page("OIDC Error", f"<p><b>Token exchange failed:</b> {desc}</p>"
                     "<p>Check your Entra app configuration and try <a href='/oidc/login'>logging in again</a>.</p>")
    if not token:
        return page("OIDC Error", "<p>Token exchange failed.</p>")

    session.pop("oidc_retry", None)
    claims = get_client().parse_id_token(token, nonce=nonce)
    session["oidc"] = {"token": token, "claims": claims}
    next_url = session.pop("login_next", None) or request.cookies.get("login_next")
    dest = next_url if next_url and next_url.startswith("/") else url_for("oidc.user")
    resp = make_response(redirect(dest))
    resp.delete_cookie("login_next")
    return resp

@bp.get("/user")
def user() -> ResponseReturnValue:
    data = session.get("oidc")
    if not data:
        return page("OIDC User", "<p>Not signed in. <a href='/oidc/login'>Login</a></p>")

    # Show full access_token only if requested
    show_full = (
        str(request.args.get("showtoken", "")).lower() in ("1", "true", "yes")
        or str(os.getenv("SHOW_FULL_COOKIES", "")).lower() in ("1", "true", "yes")
    )

    raw_token = data.get("token", {}) or {}
    token_for_display = dict(raw_token)
    if not show_full and "access_token" in token_for_display and token_for_display["access_token"]:
        token_for_display["access_token"] = redact(token_for_display["access_token"], head=8, tail=8, mask_char="*")

    body = (
    "<h2>ID Token Claims</h2><pre class='code'>" + pretty_json(data["claims"]) + "</pre>"
    "<h2>Token Set</h2><pre class='code'>" + pretty_json(token_for_display) + "</pre>"
    )

    if not show_full and "access_token" in raw_token:
        body += (
            "<p style='color:#a00'><b>Note:</b> The <code>access_token</code> is masked by default. "
            "Append <code>?showtoken=1</code> to this URL or set env <code>SHOW_FULL_TOKENS=1</code> to reveal.</p>"
        )

    body += "<p><a href='/oidc/logout'>OIDC Logout</a></p>"
    return page("OIDC User", body)

@bp.get("/logout")
def logout() -> ResponseReturnValue:
    session.pop("oidc", None)
    end_session = (
        f"https://login.microsoftonline.com/{settings.TENANT_ID}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={settings.BASE_URL}"
    )
    return redirect(end_session)

@bp.get("/logout-url")
def logout_url() -> ResponseReturnValue:
    # Allow override; default to tenant authority
    authority = request.args.get("authority") or f"https://login.microsoftonline.com/{settings.TENANT_ID}/v2.0"
    discovery = f"{authority.rstrip('/')}/.well-known/openid-configuration"

    # Try discovery; fall back to static endpoint if missing
    try:
        r = requests.get(discovery, timeout=6); r.raise_for_status()
        end_session = r.json().get("end_session_endpoint")
    except Exception:
        end_session = None
    if not end_session:
        end_session = f"https://login.microsoftonline.com/{settings.TENANT_ID}/oauth2/v2.0/logout"

    plru = request.args.get("post_logout_redirect_uri") or settings.BASE_URL
    id_token_hint = request.args.get("id_token_hint")
    q = {"post_logout_redirect_uri": plru}
    if id_token_hint:
        q["id_token_hint"] = id_token_hint
    url = f"{end_session}?{urlencode(q)}"

    # Optional immediate redirect
    if str(request.args.get("redirect", "")).lower() in ("1", "true", "yes"):
        return redirect(url)

    body = "<h2>OIDC Logout URL</h2><pre>" + url + "</pre>"
    return page("OIDC Logout URL", body)

