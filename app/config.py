import os
from os.path import expandvars
from dotenv import load_dotenv

load_dotenv()

def _clean(v: str | None, default: str = "") -> str:
    if v is None:
        return default
    s = v.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s

def _federation_metadata_url(tenant_id: str, app_id: str) -> str:
    """
    Build Entra's 'App Federation Metadata Url' from tenant and Enterprise App ID.
    Example:
      https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml?appid=<appId>
    """
    base = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
    return f"{base}?appid={app_id}"

class Settings:
    PORT = int(_clean(os.getenv("PORT", "3000")))
    SESSION_SECRET = _clean(os.getenv("SESSION_SECRET", "change-me-in-prod"))
    BASE_URL = _clean(os.getenv("BASE_URL", f"http://localhost:{PORT}")).rstrip("/")
    POST_LOGOUT_REDIRECT_URI = _clean(os.getenv("POST_LOGOUT_REDIRECT_URI","http://localhost:3000/"))

    TENANT_ID = _clean(os.getenv("TENANT_ID", "YOUR_TENANT_ID"))
    OIDC_CLIENT_ID = _clean(os.getenv("OIDC_CLIENT_ID", "YOUR_OIDC_CLIENT_ID"))
    OIDC_CLIENT_SECRET = _clean(os.getenv("OIDC_CLIENT_SECRET", "YOUR_OIDC_CLIENT_SECRET"))
    OIDC_REDIRECT_URI = _clean(os.getenv("OIDC_REDIRECT_URI", (BASE_URL + "/oidc/callback")))
    OIDC_AUTHORITY= _clean(os.getenv("OIDC_AUTHORITY","https://login.microsoftonline.com/common/v2.0"))
    OIDC_EXPECTED_AUDIENCE = OIDC_CLIENT_ID

    OIDC_METADATA_URL = _clean(os.getenv("OIDC_METADATA_URL",
        f"https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration"))
    OIDC_SCOPES = _clean(os.getenv("OIDC_SCOPES", "openid profile email"))

    SAML_SP_ENTITY_ID = _clean(os.getenv("SAML_SP_ENTITY_ID", "urn:entra-protocol-lab:sp"))
    SAML_APP_ID = _clean(os.getenv("SAML_APP_ID", "SAML_APP_ID"))
    SAML_SIGN_REQUEST = _clean(os.getenv("SAML_SIGN_REQUEST", "false")).lower() == "true"
    SAML_IDP_METADATA_URL = _clean(os.getenv("SAML_IDP_METADATA_URL",
        _federation_metadata_url(TENANT_ID, SAML_APP_ID)))


settings = Settings()

# ---------------------------------------------------------------------------
# Runtime override helpers (in-memory only, lost on restart)
# ---------------------------------------------------------------------------

_CONFIGURABLE_KEYS = frozenset({
    "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL",
    "OIDC_REDIRECT_URI", "OIDC_SCOPES",
    "SAML_SP_ENTITY_ID", "SAML_IDP_METADATA_URL", "SAML_SIGN_REQUEST",
})


def runtime_set(key: str, value) -> None:
    """Set a runtime override on the settings instance (shadows the class attr)."""
    if key not in _CONFIGURABLE_KEYS:
        raise ValueError(f"Key {key!r} is not runtime-configurable")
    setattr(settings, key, value)


def runtime_get_all() -> dict:
    """Return current effective values for all configurable keys."""
    return {k: getattr(settings, k, "") for k in sorted(_CONFIGURABLE_KEYS)}


def runtime_reset() -> None:
    """Remove all runtime overrides, restoring env / defaults."""
    for key in _CONFIGURABLE_KEYS:
        try:
            delattr(settings, key)
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# IDP certificate override (in-memory only, lost on restart)
# Stored in a named temp file so pysaml2 can reference it by path.
# ---------------------------------------------------------------------------

import tempfile as _tempfile
import os as _os

_idp_cert_pem: "str | None" = None
_idp_cert_tmp_path: "str | None" = None
# Preserve whatever REQUESTS_CA_BUNDLE was set before any cert upload,
# so we can restore it cleanly on clear.
_original_ca_bundle: "str | None" = _os.environ.get("REQUESTS_CA_BUNDLE")


def set_idp_cert(pem: str) -> str:
    """Store a PEM certificate for the IDP, write to a temp file, return the path.

    Also sets REQUESTS_CA_BUNDLE so that pysaml2 and all other requests-based
    HTTP calls automatically trust the cert for the lifetime of the process.
    """
    global _idp_cert_pem, _idp_cert_tmp_path
    _clear_cert_file()
    _idp_cert_pem = pem
    fd, path = _tempfile.mkstemp(prefix="idp_cert_", suffix=".pem")
    with _os.fdopen(fd, "w") as f:
        f.write(pem)
    _idp_cert_tmp_path = path
    _os.environ["REQUESTS_CA_BUNDLE"] = path
    return path


def get_idp_cert_path() -> "str | None":
    """Return the temp-file path of the current IDP cert, or None if not set."""
    return _idp_cert_tmp_path


def get_idp_cert_pem() -> "str | None":
    """Return the raw PEM string of the current IDP cert, or None."""
    return _idp_cert_pem


def clear_idp_cert() -> None:
    """Remove the in-memory IDP cert, delete the temp file, and restore REQUESTS_CA_BUNDLE."""
    global _idp_cert_pem, _idp_cert_tmp_path
    _clear_cert_file()
    _idp_cert_pem = None
    _idp_cert_tmp_path = None
    # Restore the env var to its original state (pre-upload)
    if _original_ca_bundle is None:
        _os.environ.pop("REQUESTS_CA_BUNDLE", None)
    else:
        _os.environ["REQUESTS_CA_BUNDLE"] = _original_ca_bundle


def _clear_cert_file() -> None:
    global _idp_cert_tmp_path
    if _idp_cert_tmp_path and _os.path.exists(_idp_cert_tmp_path):
        try:
            _os.unlink(_idp_cert_tmp_path)
        except OSError:
            pass