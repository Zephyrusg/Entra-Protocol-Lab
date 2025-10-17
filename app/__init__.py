# app/__init__.py
from flask import Flask, request
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse
import os
from .config import settings
from .oidc.client import init_oauth
from .oidc.routes import bp as oidc_bp
from .saml.routes import bp as saml_bp

def is_local_dev():
    env = str(getattr(settings, "ENV", os.getenv("FLASK_ENV", ""))).lower()
    base = str(getattr(settings, "BASE_URL", ""))
    host = urlparse(base).hostname or ""
    return (
        env in {"dev", "development", "local"}
        or host in {"localhost", "127.0.0.1"}
        or base.startswith("http://")
    )

_BASE_HOST = urlparse(getattr(settings, "BASE_URL", "")).hostname or ""

LOCAL_DEV = is_local_dev()

# ---- Security header values ----
CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'self'; "
    "form-action 'self'; "
    "connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com; "
    "img-src 'self' data: https:; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'"
)

# Derive the custom domain from BASE_URL = "https://entralab.basdk.nl"
def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = settings.SESSION_SECRET

    # Sessions: required flags for OIDC/SAML (ACS is a cross-site POST)
    app.config.update(
        SESSION_TYPE="filesystem",
        SESSION_FILE_DIR="/tmp/flask-sessions",
        SESSION_PERMANENT=False,
        SESSION_COOKIE_SECURE=not LOCAL_DEV,                      # False on localhost HTTP
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=("Lax" if LOCAL_DEV else "None"), # Lax for dev, None for prod
    )
    Session(app)

    # Trust Azure Container Apps ingress (X-Forwarded-*)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # OAuth / SAML
    init_oauth(app)
    app.register_blueprint(oidc_bp, url_prefix="/oidc")
    app.register_blueprint(saml_bp, url_prefix="/saml")

    # Security headers on every response
    @app.after_request
    def set_security_headers(resp):
        # Start with Report-Only while testing if you prefer:
        # resp.headers["Content-Security-Policy-Report-Only"] = CSP
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
            "accelerometer=(), gyroscope=(), magnetometer=()"
        )
        xf_host = request.headers.get("X-Forwarded-Host", request.host.split(":")[0])
        xf_proto = request.headers.get("X-Forwarded-Proto", "http")

        # HSTS only when original request was HTTPS and host is your custom domain
        
        if not LOCAL_DEV and xf_proto == "https" and xf_host == _BASE_HOST:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    # Index (optional)
    from .utils.html import page
    @app.get("/")
    def index():
        return page(
            "Entra Protocol Lab (Python)",
            f"<p>Test <b>OIDC</b> and <b>SAML</b> against Entra.</p>"
            f"<ul><li>OIDC: <code>/oidc/login</code> → <code>/oidc/user</code></li>"
            f"<li>SAML: <code>/saml/login</code> → <code>/saml/user</code></li></ul>"
            f"<p><b>BASE_URL:</b> {settings.BASE_URL}</p>"
        )

    return app