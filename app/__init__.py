from flask import Flask
from flask_session import Session
from .config import settings   # a simple object or module with your env values
from .oidc.client import init_oauth
from .oidc.routes import bp as oidc_bp
from .saml.routes import bp as saml_bp

def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = settings.SESSION_SECRET
    app.config.update(
        SESSION_TYPE="filesystem",
        SESSION_FILE_DIR="/tmp/flask-sessions",
        SESSION_PERMANENT=False,
    )
    Session(app)

    # Register OAuth providers (Authlib)
    init_oauth(app)

    # Blueprints
    app.register_blueprint(oidc_bp, url_prefix="/oidc")
    app.register_blueprint(saml_bp, url_prefix="/saml")

    # Index route (optional: move to its own blueprint)
    from .utils.html import page
    @app.get("/")
    def index():
        return page("Entra Protocol Lab (Python)",
                    f"<p>Test <b>OIDC</b> and <b>SAML</b> against Entra.</p>"
                    f"<ul><li>OIDC: <code>/oidc/login</code> → <code>/oidc/user</code></li>"
                    f"<li>SAML: <code>/saml/login</code> → <code>/saml/user</code></li></ul>"
                    f"<p><b>BASE_URL:</b> {settings.BASE_URL}</p>")
    return app