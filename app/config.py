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
    SAML_IDP_ENTITY_ID = expandvars(os.getenv("SAML_IDP_ENTITY_ID", f"https://sts.windows.net/{TENANT_ID}/"))
    SAML_IDP_SSO_URL = expandvars(os.getenv("SAML_IDP_SSO_URL", f"https://login.microsoftonline.com/{TENANT_ID}/saml2"))
    SAML_IDP_CERT_B64 = os.getenv("SAML_IDP_CERT_B64", "")
    SAML_SIGN_REQUEST = os.getenv("SAML_SIGN_REQUEST", "false").lower() == "true"

settings = Settings()