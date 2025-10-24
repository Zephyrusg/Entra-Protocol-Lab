
from __future__ import annotations
import json, time, os, datetime as dt
from typing import Dict, Any, Optional, Tuple

import requests
import jwt
from jwt import algorithms
from flask import Blueprint, request, jsonify, render_template_string

bp = Blueprint("tools_jwt", __name__, url_prefix="/tools/jwt")

HTTP_TIMEOUT = 6
CLOCK_SKEW = 120
DEFAULT_OIDC_AUTHORITY = os.getenv("OIDC_AUTHORITY", "https://login.microsoftonline.com/common/v2.0")
DEFAULT_EXPECTED_AUDIENCE = os.getenv("OIDC_EXPECTED_AUDIENCE")

class _TTLCache:
    def __init__(self, ttl: int = 600):
        self.ttl = ttl
        self._s: Dict[str, Tuple[float, Any]] = {}
    def get(self, k: str):
        v = self._s.get(k)
        if not v:
            return None
        exp, val = v
        if time.time() > exp:
            self._s.pop(k, None)
            return None
        return val
    def set(self, k: str, val: Any):
        self._s[k] = (time.time() + self.ttl, val)

disc_cache, jwks_cache = _TTLCache(), _TTLCache()

def _get_json(url: str):
    t0 = time.perf_counter()
    r = requests.get(url, timeout=HTTP_TIMEOUT)
    lat = (time.perf_counter() - t0) * 1000
    r.raise_for_status()
    return r.json(), r.headers, lat

def get_openid_config(authority: str) -> dict:
    authority = authority.rstrip("/")
    url = f"{authority}/.well-known/openid-configuration"
    c = disc_cache.get(url)
    if c:
        return c
    data, _, _ = _get_json(url)
    disc_cache.set(url, data)
    return data

def get_jwks(jwks_uri: str) -> dict:
    c = jwks_cache.get(jwks_uri)
    if c:
        return c
    data, _, _ = _get_json(jwks_uri)
    jwks_cache.set(jwks_uri, data)
    return data

def pick_key_from_jwks(jwks: dict, kid: Optional[str]):
    keys = jwks.get("keys", [])
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return kid, algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
    for k in keys:
        if k.get("kty") == "RSA":
            try:
                return k.get("kid"), algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
            except Exception:
                pass
    return None, None

@bp.route("/validate", methods=["OPTIONS", "POST"])
def jwt_validate_route():
    if request.method == "OPTIONS":
        return ("", 204, {"Access-Control-Allow-Origin": "*",
                          "Access-Control-Allow-Headers": "Content-Type",
                          "Access-Control-Allow-Methods": "POST, OPTIONS"})
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    authority = data.get("authority") or DEFAULT_OIDC_AUTHORITY
    expected_aud = data.get("expected_aud") or DEFAULT_EXPECTED_AUDIENCE
    if not token:
        return jsonify({"error": "Missing 'token'"}), 400

    res: Dict[str, Any] = {
        "valid": False, "sig_ok": False, "exp_ok": False, "nbf_ok": True,
        "aud_ok": False, "iss_ok": False, "errors": [], "warnings": [],
        "header": {}, "claims": {}, "authority": authority,
        "received_at_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
    }
    try:
        res["header"] = jwt.get_unverified_header(token)
        res["claims"] = jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
    except Exception as ex:
        res["errors"].append(f"Failed to parse token: {ex}")
        return jsonify(res), 400

    try:
        cfg = get_openid_config(authority)
        res["jwks_uri"] = cfg.get("jwks_uri")
        res["issuer_expected"] = cfg.get("issuer")
        jwks = get_jwks(res["jwks_uri"])
        used_kid, key = pick_key_from_jwks(jwks, res["header"].get("kid"))
        res["kid_used"] = used_kid
        if not key:
            raise ValueError("No suitable key in JWKS")
        verify_opts = {"algorithms": [res["header"].get("alg", "RS256")], "issuer": res["issuer_expected"], "leeway": CLOCK_SKEW}
        if expected_aud:
            claims = jwt.decode(token, key=key, audience=expected_aud, **verify_opts)
            res["aud_ok"] = True
        else:
            claims = jwt.decode(token, key=key, options={"verify_aud": False}, **verify_opts)
            res["warnings"].append("No audience provided; aud not verified")
        res.update({"sig_ok": True, "iss_ok": True, "claims": claims})
        now = int(time.time())
        exp, nbf = claims.get("exp"), claims.get("nbf")
        res["exp_ok"] = True if exp is None else (exp + CLOCK_SKEW) >= now
        res["nbf_ok"] = True if nbf is None else (nbf - CLOCK_SKEW) <= now
        res["valid"] = res["sig_ok"] and res["iss_ok"] and res["exp_ok"] and res["nbf_ok"] and (res["aud_ok"] or expected_aud is None)
    except jwt.ExpiredSignatureError:
        res["exp_ok"] = False; res["errors"].append("Token expired (exp)")
    except jwt.ImmatureSignatureError:
        res["nbf_ok"] = False; res["errors"].append("Token not yet valid (nbf)")
    except jwt.InvalidAudienceError:
        res["aud_ok"] = False; res["errors"].append("Invalid audience (aud)")
    except jwt.InvalidIssuerError:
        res["iss_ok"] = False; res["errors"].append("Invalid issuer (iss)")
    except jwt.InvalidSignatureError:
        res["sig_ok"] = False; res["errors"].append("Invalid signature")
    except Exception as ex:
        res["errors"].append(f"Validation error: {ex}")

    c = res.get("claims", {})
    if "xms_cc" in c:
        res["warnings"].append("CAE claim present (xms_cc)")
    if isinstance(c.get("groups"), list) and any(len(g)==36 for g in c["groups"]):
        res["warnings"].append("Groups appear as GUIDs; resolve names via Graph if needed")
    if "roles" in c:
        res["warnings"].append("App roles present; prefer roles over scp when possible")

    return jsonify(res), (200 if res.get("valid") else 400)

@bp.get("/ui")
def ui_jwt():
    html = """
<!doctype html><meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>JWT Validator • Entra Test App</title>
<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:24px}.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}textarea,input{width:100%}textarea{height:180px}pre{background:#1118270d;padding:12px;border-radius:8px;overflow:auto}.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#eee;margin-right:6px}.ok{background:#d1fae5}.warn{background:#fef3c7}.fail{background:#fee2e2}.card{border:1px solid #e5e7eb;border-radius:12px;padding:16px}button{padding:8px 12px;border-radius:8px;border:1px solid #e5e7eb;background:#111827;color:#fff;cursor:pointer}</style>
<h1>JWT Validator</h1>
<div class='row'><div class='card'>
  <label>Authority</label><input id='authority' placeholder='https://login.microsoftonline.com/common/v2.0'/>
  <label style='margin-top:8px;display:block;'>Expected Audience (Client ID)</label><input id='aud' placeholder='<your-client-id>'/>
  <label style='margin-top:8px;display:block;'>JWT</label><textarea id='token' placeholder='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'></textarea>
  <button id='btn'>Validate</button>
</div><div class='card'>
  <div id='status'></div><h3>Header</h3><pre id='hdr'></pre><h3>Claims</h3><pre id='claims'></pre><h3>Full Result</h3><pre id='raw'></pre>
</div></div>
<script src="{{ url_for('static', filename='js/jwt-ui.js') }}"></script>
"""
    return render_template_string(html)
