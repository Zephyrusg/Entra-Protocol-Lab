import ssl
import logging
import datetime
from flask import Blueprint, jsonify, request, render_template
from flask.typing import ResponseReturnValue
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ..config import (
    settings, runtime_set, runtime_get_all, runtime_reset,
    set_idp_cert, get_idp_cert_pem, clear_idp_cert,
)
from ..oidc.client import reregister_oidc

log = logging.getLogger(__name__)

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
    clear_idp_cert()
    try:
        reregister_oidc()
    except Exception:
        pass  # best-effort re-init with original env values
    return jsonify({"ok": True, "settings": runtime_get_all()})


# ---------------------------------------------------------------------------
# IDP certificate endpoints
# ---------------------------------------------------------------------------

def _cert_info(cert) -> dict:
    """Extract display-friendly info from a cryptography x509 Certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    )
    not_before = (
        cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    )
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "serial": str(cert.serial_number),
        "expired": now > not_after,
    }


@bp.post("/upload-idp-cert")
def upload_idp_cert() -> ResponseReturnValue:
    """Accept a PEM certificate (JSON body with 'pem' key, or multipart file upload)."""
    pem: str | None = None

    data = request.get_json(silent=True)
    if data and isinstance(data, dict) and data.get("pem"):
        pem = str(data["pem"]).strip()
    elif "cert_file" in request.files:
        raw = request.files["cert_file"].read(64 * 1024)  # 64 KB max
        try:
            pem = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return jsonify({"ok": False, "error": "File is not valid UTF-8 text"}), 400

    if not pem:
        return jsonify({"ok": False, "error": "No certificate provided"}), 400

    # Validate the PEM before storing
    try:
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Invalid PEM certificate: {exc}"}), 400

    set_idp_cert(pem)
    return jsonify({"ok": True, "cert": _cert_info(cert)})


@bp.post("/clear-idp-cert")
def clear_idp_cert_route() -> ResponseReturnValue:
    """Remove the uploaded IDP certificate from memory."""
    clear_idp_cert()
    return jsonify({"ok": True})


@bp.get("/idp-cert-status")
def idp_cert_status() -> ResponseReturnValue:
    """Return info about the currently loaded IDP certificate."""
    pem = get_idp_cert_pem()
    if not pem:
        return jsonify({"loaded": False})
    try:
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
        return jsonify({"loaded": True, "cert": _cert_info(cert)})
    except Exception:
        return jsonify({"loaded": False})

def _probe_url(url: str, label: str) -> dict:
    """Probe a URL and return connectivity / SSL / content status."""
    result = {"url": url, "label": label, "reachable": False,
              "ssl_ok": False, "status_code": None, "error": None,
              "content_type": None, "detail": None}
    if not url or not url.startswith("http"):
        result["error"] = "No URL configured"
        return result
    try:
        resp = requests.get(url, timeout=8)
        result["reachable"] = True
        result["ssl_ok"] = url.startswith("https://")
        result["status_code"] = resp.status_code
        result["content_type"] = resp.headers.get("Content-Type", "")
        if resp.status_code >= 400:
            result["error"] = f"HTTP {resp.status_code}"
        # For OIDC, check it looks like a discovery document
        if label == "OIDC" and resp.status_code == 200:
            try:
                data = resp.json()
                if "authorization_endpoint" in data:
                    result["detail"] = f"Valid OIDC discovery — issuer: {data.get('issuer', '?')}"
                else:
                    result["error"] = "Response is JSON but missing 'authorization_endpoint' — not a valid OIDC discovery document"
            except Exception:
                result["error"] = "Response is not valid JSON — expected an OIDC discovery document"
        # For SAML, check it looks like XML metadata
        if label == "SAML" and resp.status_code == 200:
            ct = result["content_type"].lower()
            text = resp.text[:500]
            if "xml" in ct or text.strip().startswith("<?xml") or "<EntityDescriptor" in text:
                result["detail"] = "Valid SAML metadata XML"
            else:
                result["error"] = "Response does not look like SAML metadata XML"
    except requests.exceptions.SSLError as exc:
        msg = str(exc)
        result["reachable"] = True  # network reachable, SSL failed
        result["ssl_ok"] = False
        if "CERTIFICATE_VERIFY_FAILED" in msg:
            result["error"] = "SSL certificate not trusted — the IDP uses a self-signed or untrusted CA certificate"
            # Try to extract the specific SSL reason
            cause = exc.__cause__ or exc.__context__
            while cause:
                if isinstance(cause, ssl.SSLCertVerificationError):
                    result["detail"] = cause.args[-1] if cause.args else str(cause)
                    break
                cause = cause.__cause__ or cause.__context__
        else:
            result["error"] = f"SSL error: {msg[:200]}"
        log.warning("SSL probe failed for %s (%s): %s", label, url, msg)
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connection failed — cannot reach {url}"
        result["detail"] = str(exc)[:200]
    except requests.exceptions.Timeout:
        result["error"] = "Connection timed out (8s)"
    except Exception as exc:
        result["error"] = str(exc)[:200]
    return result


@bp.post("/test")
def test_connectivity() -> ResponseReturnValue:
    """Probe configured metadata URLs and report connectivity + SSL status."""
    results = []
    oidc_url = getattr(settings, "OIDC_METADATA_URL", "")
    if oidc_url:
        results.append(_probe_url(oidc_url, "OIDC"))
    saml_url = getattr(settings, "SAML_IDP_METADATA_URL", "")
    if saml_url:
        results.append(_probe_url(saml_url, "SAML"))
    return jsonify({"results": results})
