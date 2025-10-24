from __future__ import annotations

import json
from flask import Blueprint, redirect, session, make_response, request, current_app
from flask.typing import ResponseReturnValue

from .settings import saml_client, sp_config
from ..utils.html import page, pretty_json, redact
from ..config import settings

from saml2 import BINDING_HTTP_POST
from typing import Any, Dict, List, Tuple
import os

import uuid, zlib, base64, datetime as dt
from urllib.parse import urlencode
import requests
import xml.etree.ElementTree as ET


bp = Blueprint("saml", __name__, url_prefix="/saml")

def _get_idp_slo(metadata_url: str) -> tuple[str | None, str | None]:
    """Return (HTTP-Redirect URL, HTTP-POST URL) from IdP metadata."""
    resp = requests.get(metadata_url, timeout=6)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    slo_redirect = slo_post = None
    for el in root.findall(".//md:IDPSSODescriptor/md:SingleLogoutService", ns):
        b = (el.attrib.get("Binding") or "")
        loc = el.attrib.get("Location")
        if "HTTP-Redirect" in b:
            slo_redirect = loc
        if "HTTP-POST" in b:
            slo_post = loc
    return slo_redirect, slo_post

def _build_logout_request_xml(issuer: str, destination: str, nameid: str | None, session_index: str | None) -> str:
    rid = "_" + uuid.uuid4().hex
    now = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    root = ET.Element("{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest", attrib={
        "ID": rid, "Version": "2.0", "IssueInstant": now, "Destination": destination,
    })
    ET.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text = issuer
    if nameid:
        ET.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = nameid
    if session_index:
        ET.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex").text = session_index
    return ET.tostring(root, encoding="unicode")

def _deflate_base64(s: str) -> str:
    # SAML HTTP-Redirect encoding (raw DEFLATE, base64)
    return base64.b64encode(zlib.compress(s.encode("utf-8"))[2:-4]).decode("ascii")

def _jsonable_attrs(attrs: Dict[str, List[Any]] | None) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not attrs:
        return out
    for k, vals in attrs.items():
        if isinstance(vals, (list, tuple)):
            out[k] = ["" if v is None else str(v) for v in vals]
        else:
            out[k] = ["" if vals is None else str(vals)]
    return out

def _safe_issuer(authn) -> str | None:
    # pysaml2 exposes issuer() as a METHOD
    try:
        if hasattr(authn, "issuer") and callable(authn.issuer):
            return str(authn.issuer())
    except Exception:
        pass
    return None

def _safe_authn_context(authn) -> list | str | None:
    # authn_info can be a list of tuples; normalize to strings
    info = None
    try:
        info = authn.authn_info() if callable(getattr(authn, "authn_info", None)) else getattr(authn, "authn_info", None)
    except Exception:
        info = None
    if info is None:
        return None
    if isinstance(info, (list, tuple)):
        norm = []
        for item in info:
            if isinstance(item, (list, tuple)):
                norm.append([("" if x is None else str(x)) for x in item])
            else:
                norm.append("" if item is None else str(item))
        return norm
    return "" if info is None else str(info)


@bp.get("/login")
def login() -> ResponseReturnValue:
    client = saml_client()
    reqid, info = client.prepare_for_authenticate()
    # info['headers'] is a list of (Name, Value); find the redirect Location
    for k, v in info.get("headers", []):
        if k.lower() == "location":
            return redirect(v, code=302)
    return page("SAML Error", "<p>Failed to build SAML AuthnRequest.</p>")

@bp.post("/acs")
def acs():
    client = saml_client()
    saml_response = request.form.get("SAMLResponse")
    if not saml_response:
        return page("SAML Error", "<p>Missing SAMLResponse</p>")

    try:
        authn = client.parse_authn_request_response(saml_response, BINDING_HTTP_POST)
    except Exception as e:
        return page("SAML Error", f"<p>Parse/verify failed:</p><pre>{e}</pre>")

    ident = authn.get_identity() if authn else None
    if not ident:
        return page("SAML Error", "<p>No attributes / not authenticated.</p>")

    # NameID
    nameid = None
    try:
        subj = authn.get_subject()
        nameid = getattr(subj, "text", None) or str(subj)
    except Exception:
        nameid = None

    # 🚫 Do NOT stash authn/metadata/etc. in session. Only plain data:
    session["saml_user"] = {
        "nameid": nameid,
        "attributes": _jsonable_attrs(ident),
        "issuer": _safe_issuer(authn),
        "authn_context": _safe_authn_context(authn),
    }
    return redirect("/saml/user", code=302)

@bp.get("/user")
def user() -> ResponseReturnValue:
    data = session.get("saml_user")
    if not data:
        return page("SAML User", "<p>Not signed in. <a href='/saml/login'>Login</a></p>")

    # reveal full cookie values if:
    #  - URL has ?showcookie=1|true|yes  OR
    #  - env SHOW_FULL_COOKIES=1|true|yes
    show_full = (
        str(request.args.get("showcookie", "")).lower() in ("1", "true", "yes")
        or str(os.getenv("SHOW_FULL_COOKIES", "")).lower() in ("1", "true", "yes")
    )

    cookie_header = request.headers.get("Cookie", "") or ""
    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
    session_cookie_val = request.cookies.get(cookie_name, "") or ""

    cookie_header_display = cookie_header if show_full else redact(cookie_header, head=24, tail=12)
    session_cookie_display = session_cookie_val if show_full else redact(session_cookie_val)

    # show attributes and the rest of the session-safe fields (nameid, issuer, authn_context)
    non_attr = {k: v for k, v in data.items() if k != "attributes"}

    body = (
        "<h2>Attributes</h2><pre class='code wrap'>" + pretty_json(data.get("attributes", {})) + "</pre>"
        "<h2>Session</h2><pre class='code wrap'>" + pretty_json(non_attr) + "</pre>"
        "<hr/>"
        "<h3>Cookies (incoming request)</h3>"
        f"<p><b>Cookie header:</b></p><pre class='code wrap'>" + cookie_header_display + "</pre>"
        f"<p><b>Session cookie</b> (<code>{cookie_name}</code>):</p><pre class='code wrap'>" + session_cookie_display + "</pre>"
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
    session.pop("saml_user", None)
    return redirect("/", code=302)

@bp.get("/metadata")
def metadata():
    from saml2.metadata import create_metadata_string
    from .settings import sp_config

    conf = sp_config()

    # Handle both pysaml2 signatures:
    # - new: create_metadata_string(config=conf, sign=None, ...)
    # - old: create_metadata_string(configfile, config=conf, sign=None, ...)
    try:
        xml = create_metadata_string(config=conf, sign=None)
    except TypeError:
        # Older signature needs configfile explicitly, even if None
        xml = create_metadata_string(configfile=None, config=conf, sign=None)

    # Normalize to bytes
    if isinstance(xml, str):
        xml_bytes = xml.encode("utf-8")
    else:
        xml_bytes = xml

    resp = make_response(xml_bytes, 200)
    resp.headers["Content-Type"] = "application/samlmetadata+xml"
    resp.headers["Content-Disposition"] = "attachment; filename=sp-metadata.xml"
    return resp

@bp.get("/debug/config")
def saml_debug_config():
    import os
    from .settings import sp_config  # our pysaml2 SPConfig builder

    conf = sp_config()

    # EntityID
    try:
        entityid = getattr(conf, "entityid", None) or conf.getattr("entityid", "")
    except Exception:
        entityid = ""

    # ACS endpoints (list of (url, binding))
    acs_urls = []
    try:
        endpoints = conf.getattr("endpoints", "sp") or {}
        acs_pairs = endpoints.get("assertion_consumer_service", []) or []
        for pair in acs_pairs:
            if isinstance(pair, (list, tuple)) and pair:
                acs_urls.append(str(pair[0]))
            else:
                acs_urls.append(str(pair))
    except Exception:
        pass

    # IdP metadata URL we’re using (rebuild from env, since SPConfig doesn’t expose it)
    md_url = settings.SAML_IDP_METADATA_URL

    body = (
        "<h2>SAML SP Effective Config</h2>"
        f"<p><b>EntityID:</b> {entityid}</p>"
        f"<p><b>ACS endpoints:</b></p><pre>{pretty_json(acs_urls)}</pre>"
        f"<p><b>IdP metadata URL:</b></p><pre>{pretty_json(md_url)}</pre>"
        f"<p><b>BASE_URL:</b> {os.getenv('BASE_URL')}</p>"
        f"<p><b>SAML_SP_ENTITY_ID:</b> {os.getenv('SAML_SP_ENTITY_ID')}</p>"
    )
    return page("SAML Debug Config", body)

@bp.get("/logout-url")
def logout_url():
    # Prefer env; fall back to SP config for entityID
    md_url = settings.SAML_IDP_METADATA_URL
    if not md_url:
        return page("SAML Logout", "<p>Set <code>SAML_IDP_METADATA_URL</code> to your IdP metadata URL.</p>")

    # Try to get SP EntityID
    try:
        conf = sp_config()
        issuer = getattr(conf, "entityid", None) or conf.getattr("entityid", "")
    except Exception:
        issuer = settings.SAML_SP_ENTITY_ID

    # Pull current NameID from session unless overridden by query
    sess = session.get("saml_user") or {}
    nameid = request.args.get("nameid") or sess.get("nameid")
    session_index = request.args.get("session_index")  # optional
    relay_state = request.args.get("relay_state")

    try:
        slo_redirect, slo_post = _get_idp_slo(md_url)
    except Exception as ex:
        return page("SAML Logout", f"<p>Failed to read IdP metadata:</p><pre>{ex}</pre>")

    dest = slo_redirect or slo_post
    if not dest:
        return page("SAML Logout", "<p>IdP metadata has no <code>SingleLogoutService</code>.</p>")

    lr_xml = _build_logout_request_xml(issuer=issuer, destination=dest, nameid=nameid, session_index=session_index)
    saml_request = _deflate_base64(lr_xml)

    from urllib.parse import urlencode
    q = {"SAMLRequest": saml_request}
    if relay_state:
        q["RelayState"] = relay_state
    url = f"{dest}?{urlencode(q)}"

    body = (
        "<h2>SAML Logout URL (HTTP-Redirect)</h2>"
        f"<p><a href='{url}'>Open logout</a></p>"
        "<h3>LogoutRequest</h3><pre>" + lr_xml + "</pre>"
        "<p style='color:#a00'>Note: unsigned request for demo. Add XML-DSig if your IdP requires signatures.</p>"
    )
    return page("SAML Logout Builder", body)
