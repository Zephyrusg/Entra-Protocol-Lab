import os
from os.path import expandvars
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PORT = int(os.getenv("PORT", "3000"))
    SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-in-prod")
    BASE_URL = os.getenv("BASE_URL", f"http://localhost:{PORT}").rstrip("/")

    TENANT_ID = os.getenv("TENANT_ID", "YOUR_TENANT_ID")
    OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "YOUR_OIDC_CLIENT_ID")
    OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "YOUR_OIDC_CLIENT_SECRET")
    OIDC_REDIRECT_URI = expandvars(os.getenv("OIDC_REDIRECT_URI", f"{BASE_URL}/oidc/callback"))

    SAML_SP_ENTITY_ID = os.getenv("SAML_SP_ENTITY_ID", "urn:entra-protocol-lab:sp")
    SAML_APP_ID = os.getenv("SAML_APP_ID", "SAML_APP_ID")
    SAML_SIGN_REQUEST = os.getenv("SAML_SIGN_REQUEST", "false").lower() == "true"

settings = Settings()