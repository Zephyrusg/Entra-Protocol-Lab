import os
import secrets
import textwrap
import base64, hashlib,secrets
from urllib.parse import urlparse

from flask_session import Session
from flask import Flask, redirect, request, session, make_response
from flask import Response  # type: ignore
from flask import url_for  # type: ignore
from authlib.integrations.flask_client import OAuth
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from dotenv import load_dotenv
load_dotenv()
# -------------------- Environment / Config --------------------
PORT = int(os.getenv("PORT", "3000"))
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-in-prod")

# Base URL of THIS app (used for redirects & SAML metadata)
BASE_URL = os.getenv("BASE_URL", f"http://localhost:{PORT}").rstrip("/")

# ---------- OIDC (Microsoft Entra v2) ----------
TENANT_ID = os.getenv("TENANT_ID", "YOUR_TENANT_ID")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "YOUR_OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "YOUR_OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", f"{BASE_URL}/oidc/callback")

# ---------- SAML (Enterprise App in Entra) ----------
SAML_SP_ENTITY_ID = os.getenv("SAML_SP_ENTITY_ID", "urn:entra-protocol-lab:sp")
SAML_IDP_ENTITY_ID = os.getenv("SAML_IDP_ENTITY_ID", f"https://sts.windows.net/{TENANT_ID}/")

# Typically: https://login.microsoftonline.com/<TENANT_ID>/saml2
SAML_IDP_SSO_URL = os.getenv("SAML_IDP_SSO_URL", f"https://login.microsoftonline.com/{TENANT_ID}/saml2")
# Paste the Base64 content (no headers) of Entra's SAML Signing Certificate
SAML_IDP_CERT_B64 = os.getenv("SAML_IDP_CERT_B64", "")

# Sign AuthnRequests? For a learning lab keep this off (no SP key/cert needed)
SAML_SIGN_REQUEST = os.getenv("SAML_SIGN_REQUEST", "false").lower() == "true"

# -------------------- App Setup --------------------
app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"   # stores in /tmp by default
app.config["SESSION_FILE_DIR"] = "/tmp/flask-sessions"  # optional explicit path
app.config["SESSION_PERMANENT"] = False
Session(app)
app.secret_key = SESSION_SECRET

oauth = OAuth(app)
oauth.register(
    name="entra",
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    server_metadata_url=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

# -------------------- Small HTML helper --------------------
def page(title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial;margin:2rem;max-width:980px}}
pre{{background:#111;color:#eee;padding:1rem;border-radius:8px;overflow:auto}}
a,button{{font-size:1rem}}
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:.25rem}}
</style></head>
<body>
<h1>{title}</h1>
<nav>
  <a href="/">Home</a> |
  <a href="/oidc/login">OIDC Login</a> |
  <a href="/oidc/user">OIDC User</a> |
  <a href="/saml/login">SAML Login</a> |
  <a href="/saml/user">SAML User</a> |
  <a href="/saml/metadata">SAML Metadata</a>
</nav><hr/>
{body_html}
</body></html>"""

# -------------------- Snall Helper -------------------
def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _redact(value, head: int = 8, tail: int = 4) -> str:
    """Mask sensitive strings: keep first `head` and last `tail` chars."""
    if not value:
        return ""
    v = str(value)
    if len(v) <= head + tail + 3:
        return "*" * len(v)
    return f"{v[:head]}…{v[-tail:]}"

# -------------------- Index --------------------
@app.get("/")
def index() -> str:
    return page(
        "Entra Protocol Lab (Python)",
        f"""
        <p>Test <b>OIDC</b> and <b>SAML</b> against Microsoft Entra.</p>
        <ul>
          <li>OIDC: <code>/oidc/login</code> → <code>/oidc/user</code></li>
          <li>SAML: <code>/saml/login</code> → <code>/saml/user</code></li>
        </ul>
        <p><b>BASE_URL:</b> {BASE_URL}</p>
        """,
    )

# ==================== OIDC (Auth Code + PKCE) ====================
@app.get("/oidc/login")
def oidc_login():
    verifier = secrets.token_urlsafe(64)
    session["oidc_code_verifier"] = verifier
    challenge = pkce_challenge(verifier)

    nonce = secrets.token_urlsafe(32)
    session["oidc_nonce"] = nonce

    return oauth.entra.authorize_redirect(
        redirect_uri=OIDC_REDIRECT_URI,
        code_challenge=challenge,
        code_challenge_method="S256",
        nonce=nonce,
    )


@app.get("/oidc/callback")
def oidc_callback():
    verifier = session.pop("oidc_code_verifier", None)
    nonce = session.pop("oidc_nonce", None)
    if not verifier or not nonce:
        return page("OIDC Error", "<p>Missing PKCE verifier or nonce in session.</p>")

    token = oauth.entra.authorize_access_token(code_verifier=verifier)
    if not token:
        return page("OIDC Error", "<p>Token exchange failed.</p>")

    claims = oauth.entra.parse_id_token(token, nonce=nonce)
    session["oidc"] = {"token": token, "claims": claims}
    return redirect(url_for("oidc_user"))

@app.get("/oidc/user")
def oidc_user():
    data = session.get("oidc")
    if not data:
        return page("OIDC User", '<p>Not signed in. <a href="/oidc/login">Login</a></p>')
    body = (
        "<h2>ID Token Claims</h2><pre>"
        + _pretty_json(data["claims"])
        + "</pre><h2>Raw Token Set</h2><pre>"
        + _pretty_json(data["token"])
        + "</pre><p><a href='/oidc/logout'>OIDC Logout</a></p>"
    )
    return page("OIDC User", body)

@app.get("/oidc/logout")
def oidc_logout():
    session.pop("oidc", None)
    end_session = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri={BASE_URL}"
    return redirect(end_session)

# ==================== SAML (SP) ====================
def _b64_to_pem(cert_b64: str) -> str:
    """Convert raw Base64 cert content to PEM with headers/64-char lines."""
    if not cert_b64:
        return ""
    wrapped = textwrap.fill(cert_b64.strip(), 64)
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"

def _saml_settings_dict() -> dict:
    sp_acs = f"{BASE_URL}/saml/acs"
    https_scheme = urlparse(BASE_URL).scheme == "https"

    settings = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": SAML_SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": sp_acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            # For this lab we do NOT sign requests by default.
            "authnRequestsSigned": SAML_SIGN_REQUEST,
            "wantAssertionsSigned": False,
            "wantMessageSigned": False,
        },
        "idp": {
            "entityId": SAML_IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": SAML_IDP_SSO_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _b64_to_pem(SAML_IDP_CERT_B64),
        },
        "security": {
            "authnRequestsSigned": SAML_SIGN_REQUEST,
            "wantAssertionsSigned": False,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
        # Helps toolkit build absolute URLs correctly behind HTTPS
        "contactPerson": {},
        "organization": {},
    }
    # Ensure the toolkit knows when we're on HTTPS (affects redirects)
    settings.setdefault("advanced_settings", {})
    settings["advanced_settings"]["use_base_url"] = True
    settings["advanced_settings"]["base_url"] = BASE_URL
    if https_scheme:
        settings["advanced_settings"]["https"] = "on"
    return settings

from urllib.parse import urlparse

def _prepare_flask_request():
    """Map Flask request to the dict expected by python3-saml without duplicates."""
    base = urlparse(BASE_URL)  # e.g., https://xxx.ngrok-free.app
    # Decide scheme using BASE_URL (and fall back to header if present)
    xf_proto = request.headers.get("X-Forwarded-Proto", "").lower()
    is_https = (base.scheme == "https") or (xf_proto == "https")

    return {
        "https": "on" if is_https else "off",
        # Use the public host from BASE_URL so the toolkit builds correct URLs
        "http_host": base.netloc or request.host,
        "server_port": "443" if is_https else "80",
        # IMPORTANT: only script_name; do NOT also set path_info (avoids /saml/acs/saml/acs)
        "script_name": request.path,
        # no "path_info" key here
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string,
    }


def _saml_auth():
    req = _prepare_flask_request()
    # Pass settings dict directly (supported by python3-saml)
    return OneLogin_Saml2_Auth(req, old_settings=_saml_settings_dict())

@app.get("/saml/login")
def saml_login():
    auth = _saml_auth()
    # RelayState defaults to the ACS-binding-determined return
    return redirect(auth.login())

@app.post("/saml/acs")
def saml_acs():
    auth = _saml_auth()
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return page("SAML Error", f"<p>Errors: {errors}</p><pre>{auth.get_last_error_reason()}</pre>")
    if not auth.is_authenticated():
        return page("SAML Error", "<p>Not authenticated.</p>")

    saml_data = {
        "nameid": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }
    # Optional fields (vary by toolkit version) — guard them:
    if hasattr(auth, "get_last_assertion_not_on_or_after"):
        saml_data["assertion_not_on_or_after"] = auth.get_last_assertion_not_on_or_after()
    if hasattr(auth, "get_session_expiration"):
        saml_data["session_not_on_or_after"] = auth.get_session_expiration()
    # You can also show context/issuer if available:
    if hasattr(auth, "get_issuer"):
        saml_data["issuer"] = auth.get_issuer()
    if hasattr(auth, "get_authn_context"):
        saml_data["authn_context"] = auth.get_authn_context()

    session["saml_user"] = saml_data
    return redirect(url_for("saml_user"))

@app.get("/saml/user")
def saml_user():
    data = session.get("saml_user")
    if not data:
        return page("SAML User", '<p>Not signed in. <a href="/saml/login">Login</a></p>')

    # --- cookie visibility controls ---
    # Set SHOW_FULL_COOKIES=1 in your env or pass ?showcookie=1 in the URL to reveal the full value
    show_full = os.getenv("SHOW_FULL_COOKIES", "0") == "1" or request.args.get("showcookie") == "1"

    cookie_header = request.headers.get("Cookie", "")
    cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
    session_cookie_val = request.cookies.get(cookie_name, "")

    session_cookie_display = session_cookie_val if show_full else _redact(session_cookie_val)
    cookie_header_display = cookie_header if show_full else _redact(cookie_header, head=24, tail=12)

    body = (
        "<h2>SAML Profile</h2>"
        f"<p><b>NameID:</b> {data.get('nameid')}</p>"
        "<h3>Attributes</h3><pre>"
        + _pretty_json(data.get("attributes"))
        + "</pre>"
        "<hr/>"
        "<h3>Cookies (incoming request)</h3>"
        f"<p><b>Cookie header:</b></p><pre>{cookie_header_display}</pre>"
        f"<p><b>Session cookie</b> (<code>{cookie_name}</code>):</p><pre>{session_cookie_display}</pre>"
        "<p style='color:#a00'><b>Note:</b> Cookie values are sensitive. They are masked by default. "
        "Append <code>?showcookie=1</code> to this URL or set env <code>SHOW_FULL_COOKIES=1</code> to reveal.</p>"
        "<p><a href='/saml/logout'>SAML Logout (local)</a></p>"
    )
    return page("SAML User", body)

@app.get("/saml/logout")
def saml_logout():
    # Local logout only (Entra SLO is rarely configured for simple labs)
    session.pop("saml_user", None)
    return redirect(url_for("index"))

@app.get("/saml/metadata")
def saml_metadata():
    settings = OneLogin_Saml2_Settings(settings=_saml_settings_dict(), sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) > 0:
        return make_response(f"Metadata errors: {errors}", 500)
    return Response(metadata, mimetype="application/samlmetadata+xml")

# -------------------- Helpers --------------------
def _pretty_json(obj) -> str:
    import json
    return json.dumps(obj, indent=2, sort_keys=True, default=str)

# -------------------- Main --------------------
if __name__ == "__main__":
    # For container use, bind 0.0.0.0
    app.run(host="0.0.0.0", port=PORT, debug=False)
