
from flask import Blueprint, redirect, session, make_response, request, current_app
from flask.typing import ResponseReturnValue
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from .settings import saml_auth, saml_settings
from ..utils.html import page, pretty_json, redact

from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

from typing import Any, Callable, Optional

def _maybe_call(obj: Any, name: str, *args, **kwargs):
    fn: Optional[Callable] = getattr(obj, name, None)
    return fn(*args, **kwargs) if callable(fn) else None

bp = Blueprint("saml", __name__)

@bp.get("/login")
def login() -> ResponseReturnValue:
    auth = saml_auth()
    # RelayState to /saml/user to match your original flow
    return redirect(auth.login(return_to="/saml/user"))

@bp.post("/acs")
def acs() -> ResponseReturnValue:
    auth = saml_auth()
    auth.process_response()


    errors = auth.get_errors()
    if errors:
        return page(
            "SAML Error",
            f"<p>Errors: {errors}</p><pre>{auth.get_last_error_reason() or ''}</pre>",
         )

    if not auth.is_authenticated():
        return page("SAML Error", "<p>Not authenticated.</p>")

    issuer_val = _maybe_call(auth, "get_issuer") or auth.get_settings().get_idp_data().get("entityId")
    authn_ctx_val = _maybe_call(auth, "get_authn_context")

    # Minimal profile for demo
    data = {
        "nameid": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
        "issuer": issuer_val,
        "authn_context": authn_ctx_val
,
        }
    session["saml"] = data
    return redirect("/saml/user")

@bp.get("/user")
def user() -> ResponseReturnValue:
    data = session.get("saml")
    if not data:
        return page("SAML User", "<p>Not signed in. <a href='/saml/login'>Login</a></p>")

    # decide whether to show full cookie values
    show_full = (
        str(request.args.get("showcookie", "")).lower() in ("1", "true", "yes")
        or str(os.getenv("SHOW_FULL_COOKIES", "")).lower() in ("1", "true", "yes")
    )

    cookie_header = request.headers.get("Cookie", "") or ""
    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
    session_cookie_val = request.cookies.get(cookie_name, "") or ""

    session_cookie_display = session_cookie_val if show_full else redact(session_cookie_val)
    cookie_header_display = cookie_header if show_full else redact(cookie_header, head=24, tail=12)

    body = (
        "<h2>Attributes</h2><pre>" + pretty_json(data.get("attributes", {})) + "</pre>"
        "<h2>Session</h2><pre>" + pretty_json({k: v for k, v in data.items() if k != "attributes"}) + "</pre>"
        "<hr/>"
        "<h3>Cookies (incoming request)</h3>"
        f"<p><b>Cookie header:</b></p><pre>{cookie_header_display}</pre>"
        f"<p><b>Session cookie</b> (<code>{cookie_name}</code>):</p><pre>{session_cookie_display}</pre>"
    )

    if not show_full:
        body += (
            "<p style='color:#a00'><b>Note:</b> Cookie values are sensitive. They are masked by default. "
            "Append <code>?showcookie=1</code> to this URL or set env <code>SHOW_FULL_COOKIES=1</code> to reveal.</p>"
        )

    body += "<p><a href='/saml/logout'>SAML Logout</a></p>"
    return page("SAML User", body)

@bp.get("/logout")
def logout() -> ResponseReturnValue:
    data = session.get("saml") or {}
    nameid = data.get("nameid")
    session_index = data.get("session_index")


    auth = saml_auth()
    slo_url = auth.logout(name_id=nameid, session_index=session_index, return_to="/")
    return redirect(slo_url)

@bp.get("/metadata")
def metadata() -> ResponseReturnValue:
    settings_obj = saml_settings()
    metadata = settings_obj.get_sp_metadata()
    errors = settings_obj.validate_metadata(metadata)
    if len(errors) > 0:
        return page("SAML Metadata Error", f"<pre>{errors}</pre>")


    resp = make_response(metadata, 200)
    resp.headers["Content-Type"] = "text/xml"
    # Helpful for Entra XML import
    resp.headers["Content-Disposition"] = "attachment; filename=sp-metadata.xml"
    return resp