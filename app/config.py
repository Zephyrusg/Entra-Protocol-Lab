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