from flask import Blueprint, jsonify, request, render_template
from flask.typing import ResponseReturnValue
from ..config import settings, runtime_set, runtime_get_all, runtime_reset
from ..oidc.client import reregister_oidc

bp = Blueprint("tools_idpconfig", __name__)


@bp.get("/ui")
def ui() -> ResponseReturnValue:
    return render_template("idpconfig.html")


@bp.get("/current")
def current() -> ResponseReturnValue:
    vals = runtime_get_all()
    # Convert bool back to string for JSON consistency
    if isinstance(vals.get("SAML_SIGN_REQUEST"), bool):
        vals["SAML_SIGN_REQUEST"] = vals["SAML_SIGN_REQUEST"]
    return jsonify(vals)


@bp.post("/apply")
def apply_settings() -> ResponseReturnValue:
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

    errors = []
    for key, value in data.items():
        try:
            if key == "SAML_SIGN_REQUEST":
                runtime_set(key, str(value).lower() in ("true", "1", "yes"))
            else:
                runtime_set(key, str(value))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        return jsonify({"ok": False, "error": "; ".join(errors)}), 400

    # If any OIDC key changed, re-register the OAuth client
    oidc_keys = {"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL",
                 "OIDC_REDIRECT_URI", "OIDC_SCOPES"}
    if oidc_keys & data.keys():
        try:
            reregister_oidc()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Settings saved but OIDC re-init failed: {exc}"}), 500

    return jsonify({"ok": True, "settings": runtime_get_all()})


@bp.post("/reset")
def reset_settings() -> ResponseReturnValue:
    runtime_reset()
    try:
        reregister_oidc()
    except Exception:
        pass  # best-effort re-init with original env values
    return jsonify({"ok": True, "settings": runtime_get_all()})
