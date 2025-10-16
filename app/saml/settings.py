import textwrap
from typing import cast
from urllib.parse import urlparse
from flask import request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from ..config import settings
from .types import _SamlAuthProto
import os
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

BASE_URL = settings.BASE_URL  # e.g., http://localhost:3000 or https://xxx.ngrok-free.app
SAML_SP_ENTITY_ID = settings.SAML_SP_ENTITY_ID
SAML_SIGN_REQUEST = settings.SAML_SIGN_REQUEST

def _build_ms_metadata_url(tenant_id: str, app_id: str | None) -> str:
    base = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
    return f"{base}?appid={app_id}" if app_id else base

def _load_idp_from_metadata() -> dict:
    """
    Returns an 'idp' dict for python3-saml settings by parsing Entra's federation metadata.
    Prefers explicit metadata URL; else builds it from TENANT_ID (+ optional SAML_APP_ID).
    """
    # Prefer explicit URL if you set it
    explicit_url = getattr(settings, "SAML_IDP_METADATA_URL", None) or os.getenv("SAML_IDP_METADATA_URL")

    if explicit_url:
        url = explicit_url
    else:
        tenant_id = getattr(settings, "TENANT_ID", None) or os.getenv("TENANT_ID")
        if not tenant_id:
            raise RuntimeError("TENANT_ID (or SAML_IDP_METADATA_URL) is required to load SAML IdP metadata.")
        # If your SAML app has a different App (client) ID than OIDC, set SAML_APP_ID
        app_id = getattr(settings, "SAML_APP_ID", None)
        url = _build_ms_metadata_url(tenant_id, app_id)

    idp_parsed = OneLogin_Saml2_IdPMetadataParser.parse_remote(url, validate_cert=True, timeout=10)
    # idp_parsed = {"idp": {"entityId": "...", "singleSignOnService": {"url": "..."}, "x509cert" or "x509certMulti": ...}}
    return idp_parsed["idp"]

def _b64_to_pem(cert_b64: str) -> str:
    if not cert_b64:
        return ""
    s = cert_b64.strip()
    if "BEGIN CERTIFICATE" in s:
        return s if s.endswith("\n") else s + "\n"
    wrapped = textwrap.fill(s, 64)
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"

def _saml_settings_dict() -> dict:
    sp_acs = f"{BASE_URL}/saml/acs"
    https_scheme = urlparse(BASE_URL).scheme == "https"

    settings = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId":SAML_SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": sp_acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            # For this lab we do NOT sign requests by default.
            "authnRequestsSigned": SAML_SIGN_REQUEST,
            "wantAssertionsSigned": False,
            "wantMessageSigned": False,
        },
        "idp": _load_idp_from_metadata(),
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

def _prepare_flask_request():
    """Map Flask request to the dict expected by python3-saml without duplicates."""
    base = urlparse(settings.BASE_URL)  # e.g., https://xxx.ngrok-free.app
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

def saml_settings() -> OneLogin_Saml2_Settings:
    return OneLogin_Saml2_Settings(settings=_saml_settings_dict(), sp_validation_only=False)

def saml_auth() -> _SamlAuthProto:
    req = _prepare_flask_request()
    return cast(_SamlAuthProto, OneLogin_Saml2_Auth(req, old_settings=_saml_settings_dict()))
