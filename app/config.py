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

class Settings:
    PORT = int(_clean(os.getenv("PORT", "3000")))
    SESSION_SECRET = _clean(os.getenv("SESSION_SECRET", "change-me-in-prod"))
    BASE_URL = _clean(os.getenv("BASE_URL", f"http://localhost:{PORT}")).rstrip("/")

    TENANT_ID = _clean(os.getenv("TENANT_ID", "YOUR_TENANT_ID"))
    OIDC_CLIENT_ID = _clean(os.getenv("OIDC_CLIENT_ID", "YOUR_OIDC_CLIENT_ID"))
    OIDC_CLIENT_SECRET = _clean(os.getenv("OIDC_CLIENT_SECRET", "YOUR_OIDC_CLIENT_SECRET"))
    OIDC_REDIRECT_URI = _clean(os.getenv("OIDC_REDIRECT_URI", (BASE_URL + "/oidc/callback")))

    SAML_SP_ENTITY_ID = _clean(os.getenv("SAML_SP_ENTITY_ID", "urn:entra-protocol-lab:sp"))
    SAML_APP_ID = _clean(os.getenv("SAML_APP_ID", "SAML_APP_ID"))
    SAML_SIGN_REQUEST = _clean(os.getenv("SAML_SIGN_REQUEST", "false")).lower() == "true"

settings = Settings()