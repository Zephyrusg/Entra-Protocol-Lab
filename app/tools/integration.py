"""Integration Checker – validate OIDC / SAML tokens against an app profile.

Routes
------
GET  /tools/integration/ui              Interactive UI
POST /tools/integration/validate        JSON API
GET  /tools/integration/presets         List available presets
GET  /tools/integration/session/oidc    Return OIDC claims from current session
GET  /tools/integration/session/saml    Return SAML attributes from current session
"""

from __future__ import annotations

import json, re, fnmatch
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request, session, render_template_string
from ..utils.html import page

bp = Blueprint("tools_integration", __name__, url_prefix="/tools/integration")

# ---------------------------------------------------------------------------
# Presets – each preset describes what a target application expects
# ---------------------------------------------------------------------------

PRESETS: Dict[str, Dict[str, Any]] = {
    "vcloud_director_saml": {
        "name": "VMware Cloud Director (SAML)",
        "protocol": "saml",
        "description": "VMware Cloud Director SAML SSO integration with Entra ID",
        "required_claims": [
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        ],
        "optional_claims": [
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        ],
        "expected_values": {},
        "claim_patterns": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": r".+@.+\..+",
        },
        "required_groups": [],
        "required_roles": [],
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "guidance": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
                "Add claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add 'emailaddress' mapped to user.mail",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
                "Add claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add 'name' mapped to user.userprincipalname",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":
                "Add claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add 'surname' mapped to user.surname",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":
                "Add claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add 'givenname' mapped to user.givenname",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":
                "Add groups claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add a group claim → Select 'Groups assigned to the application'",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
                "Add roles: Entra → App Registrations → [app] → App roles → Create role, then assign users/groups in Enterprise Apps → Users and groups",
            "_nameid":
                "Set NameID: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Edit Name Identifier → Choose 'user.mail' with format 'Email address'",
            "_groups":
                "Assign group: Entra → Enterprise Apps → [app] → Users and groups → Add user/group → Select the required group",
        },
    },
    "vcloud_director_oidc": {
        "name": "VMware Cloud Director (OIDC)",
        "protocol": "oidc",
        "description": "VMware Cloud Director OIDC integration with Entra ID",
        "required_claims": [
            "email",
            "name",
            "preferred_username",
            "sub",
        ],
        "optional_claims": [
            "groups",
            "roles",
        ],
        "expected_values": {},
        "claim_patterns": {
            "email": r".+@.+\..+",
        },
        "required_groups": [],
        "required_roles": [],
        "nameid_format": None,
        "guidance": {
            "email":
                "Add optional claim: Entra → App Registrations → [app] → Token configuration → Add optional claim → ID token → email",
            "name":
                "The 'name' claim is included by default. If missing, check: Entra → App Registrations → [app] → Token configuration",
            "preferred_username":
                "The 'preferred_username' claim is included by default. If missing, check token configuration.",
            "groups":
                "Add groups claim: Entra → App Registrations → [app] → Token configuration → Add groups claim → Select 'Groups assigned to the application'",
            "roles":
                "Add roles: Entra → App Registrations → [app] → App roles → Create role, then assign in Enterprise Apps → Users and groups",
            "_groups":
                "Assign group: Entra → Enterprise Apps → [app] → Users and groups → Add user/group → Select the required group",
            "_audience":
                "Check audience: Entra → App Registrations → [app] → Overview → Application (client) ID, or Expose an API → Application ID URI",
            "_issuer":
                "Check issuer: Ensure your OIDC authority matches your tenant. Expected format: https://login.microsoftonline.com/{tenant-id}/v2.0",
        },
    },
}

# ---------------------------------------------------------------------------
# Generic guidance for common failures
# ---------------------------------------------------------------------------

_GENERIC_GUIDANCE = {
    "missing_claim_oidc":
        "Add the claim: Entra → App Registrations → [app] → Token configuration → Add optional claim",
    "missing_claim_saml":
        "Add the claim: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Add new claim",
    "wrong_audience":
        "Check Application ID: Entra → App Registrations → [app] → Overview → Application (client) ID",
    "wrong_issuer":
        "Check your authority/tenant: Entra → App Registrations → [app] → Endpoints",
    "missing_group":
        "Assign the group: Entra → Enterprise Apps → [app] → Users and groups → Add user/group",
    "missing_role":
        "Create/assign role: Entra → App Registrations → [app] → App roles → Create role, then assign in Enterprise Apps",
    "wrong_nameid":
        "Change NameID: Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims → Edit Name Identifier format",
    "value_mismatch":
        "Check the claim mapping value in Entra → Enterprise Apps → [app] → Single sign-on → Attributes & Claims",
}

# ---------------------------------------------------------------------------
# Validation engine
# ---------------------------------------------------------------------------

def _check(status: str, label: str, message: str, guidance: str = "") -> dict:
    return {"status": status, "label": label, "message": message, "guidance": guidance}


def _get_claim_value(claims: dict, key: str) -> Any:
    """Look up a claim by exact key, or fall back to short-name matching for SAML URIs."""
    if key in claims:
        return claims[key]
    # For SAML: try matching the last segment of a URI claim key
    short = key.rsplit("/", 1)[-1].lower() if "/" in key else None
    if short:
        for k, v in claims.items():
            if k.rsplit("/", 1)[-1].lower() == short:
                return v
    return None


def validate_profile(protocol: str, claims: dict, profile: dict) -> List[dict]:
    """Run all checks and return a list of result dicts."""
    results: List[dict] = []
    guidance_map = profile.get("guidance", {})

    # 1. Required claims
    for claim in profile.get("required_claims", []):
        val = _get_claim_value(claims, claim)
        short_name = claim.rsplit("/", 1)[-1] if "/" in claim else claim
        if val is None:
            hint = guidance_map.get(claim) or guidance_map.get(short_name) or (
                _GENERIC_GUIDANCE["missing_claim_saml"] if protocol == "saml"
                else _GENERIC_GUIDANCE["missing_claim_oidc"]
            )
            results.append(_check("fail", f"Claim: {short_name}", f"Required claim '{claim}' is missing", hint))
        else:
            display = val if isinstance(val, str) else json.dumps(val, default=str)
            if len(str(display)) > 120:
                display = str(display)[:117] + "..."
            results.append(_check("pass", f"Claim: {short_name}", f"Present — value: {display}"))

    # 2. Optional claims
    for claim in profile.get("optional_claims", []):
        val = _get_claim_value(claims, claim)
        short_name = claim.rsplit("/", 1)[-1] if "/" in claim else claim
        if val is None:
            hint = guidance_map.get(claim) or guidance_map.get(short_name) or ""
            results.append(_check("warn", f"Claim: {short_name} (optional)", f"Optional claim '{claim}' is not present", hint))
        else:
            display = val if isinstance(val, str) else json.dumps(val, default=str)
            if len(str(display)) > 120:
                display = str(display)[:117] + "..."
            results.append(_check("pass", f"Claim: {short_name} (optional)", f"Present — value: {display}"))

    # 3. Expected literal values
    for claim, expected in profile.get("expected_values", {}).items():
        val = _get_claim_value(claims, claim)
        short_name = claim.rsplit("/", 1)[-1] if "/" in claim else claim
        if val is None:
            results.append(_check("fail", f"Value: {short_name}", f"Claim '{claim}' is missing (expected '{expected}')",
                                  guidance_map.get(claim, _GENERIC_GUIDANCE.get("value_mismatch", ""))))
        elif str(val) != str(expected):
            results.append(_check("fail", f"Value: {short_name}",
                                  f"Expected '{expected}', got '{val}'",
                                  guidance_map.get(claim, _GENERIC_GUIDANCE.get("value_mismatch", ""))))
        else:
            results.append(_check("pass", f"Value: {short_name}", f"Matches expected value: {expected}"))

    # 4. Claim value patterns (regex)
    for claim, pattern in profile.get("claim_patterns", {}).items():
        val = _get_claim_value(claims, claim)
        short_name = claim.rsplit("/", 1)[-1] if "/" in claim else claim
        if val is None:
            continue  # already reported in required/optional
        val_str = val if isinstance(val, str) else json.dumps(val, default=str)
        if re.search(pattern, val_str):
            results.append(_check("pass", f"Pattern: {short_name}", f"Value '{val_str}' matches pattern"))
        else:
            results.append(_check("fail", f"Pattern: {short_name}",
                                  f"Value '{val_str}' does not match expected pattern '{pattern}'",
                                  guidance_map.get(claim, _GENERIC_GUIDANCE.get("value_mismatch", ""))))

    # 5. Required groups
    group_claim = _get_claim_value(claims, "groups") or _get_claim_value(
        claims, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    )
    group_list = group_claim if isinstance(group_claim, list) else (
        [group_claim] if group_claim else []
    )
    for grp in profile.get("required_groups", []):
        if grp and grp in group_list:
            results.append(_check("pass", f"Group: {grp}", "User is a member of required group"))
        elif grp:
            results.append(_check("fail", f"Group: {grp}", f"User is NOT a member of group '{grp}'",
                                  guidance_map.get("_groups", _GENERIC_GUIDANCE["missing_group"])))

    # 6. Required roles
    role_claim = _get_claim_value(claims, "roles") or _get_claim_value(
        claims, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    )
    role_list = role_claim if isinstance(role_claim, list) else (
        [role_claim] if role_claim else []
    )
    for role in profile.get("required_roles", []):
        if role and role in role_list:
            results.append(_check("pass", f"Role: {role}", "Role is present"))
        elif role:
            results.append(_check("fail", f"Role: {role}", f"Required role '{role}' is missing",
                                  guidance_map.get("_roles", _GENERIC_GUIDANCE["missing_role"])))

    # 7. NameID format (SAML only)
    expected_nameid = profile.get("nameid_format")
    if expected_nameid and protocol == "saml":
        actual = claims.get("_nameid_format") or claims.get("nameid_format")
        if actual is None:
            results.append(_check("warn", "NameID Format",
                                  "NameID format could not be determined from session data",
                                  guidance_map.get("_nameid", _GENERIC_GUIDANCE["wrong_nameid"])))
        elif actual == expected_nameid:
            results.append(_check("pass", "NameID Format", f"Correct: {actual}"))
        else:
            results.append(_check("fail", "NameID Format",
                                  f"Expected '{expected_nameid}', got '{actual}'",
                                  guidance_map.get("_nameid", _GENERIC_GUIDANCE["wrong_nameid"])))

    # 8. Issuer check (OIDC)
    expected_issuer = profile.get("expected_issuer")
    if expected_issuer and protocol == "oidc":
        actual_iss = claims.get("iss")
        if actual_iss == expected_issuer:
            results.append(_check("pass", "Issuer", f"Matches: {actual_iss}"))
        elif actual_iss:
            results.append(_check("fail", "Issuer",
                                  f"Expected '{expected_issuer}', got '{actual_iss}'",
                                  guidance_map.get("_issuer", _GENERIC_GUIDANCE["wrong_issuer"])))

    # 9. Audience check (OIDC)
    expected_aud = profile.get("expected_audience")
    if expected_aud and protocol == "oidc":
        actual_aud = claims.get("aud")
        if actual_aud == expected_aud:
            results.append(_check("pass", "Audience", f"Matches: {actual_aud}"))
        elif actual_aud:
            results.append(_check("fail", "Audience",
                                  f"Expected '{expected_aud}', got '{actual_aud}'",
                                  guidance_map.get("_audience", _GENERIC_GUIDANCE["wrong_audience"])))

    return results

# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@bp.get("/presets")
def list_presets():
    """Return the list of available presets."""
    out = {}
    for key, preset in PRESETS.items():
        out[key] = {
            "name": preset["name"],
            "protocol": preset["protocol"],
            "description": preset.get("description", ""),
        }
    return jsonify(out)


@bp.get("/session/oidc")
def session_oidc():
    """Return OIDC claims from current session (if logged in)."""
    data = session.get("oidc")
    if not data:
        return jsonify({"error": "No OIDC session. Login via /oidc/login first."}), 404
    return jsonify({"claims": data.get("claims", {}), "source": "session"})


@bp.get("/session/saml")
def session_saml():
    """Return SAML attributes from current session (if logged in)."""
    data = session.get("saml_user")
    if not data:
        return jsonify({"error": "No SAML session. Login via /saml/login first."}), 404
    # Flatten SAML attributes: saml attrs are {uri: [val, ...]}
    attrs = data.get("attributes", {})
    flat: Dict[str, Any] = {}
    for k, v in attrs.items():
        flat[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
    # Include nameid info if available
    if data.get("nameid"):
        flat["_nameid"] = data["nameid"]
    details = data.get("assertion_details", {})
    if details.get("nameid_format"):
        flat["_nameid_format"] = details["nameid_format"]
    return jsonify({"claims": flat, "source": "session"})


@bp.route("/validate", methods=["OPTIONS", "POST"])
def validate_route():
    if request.method == "OPTIONS":
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
        })

    data = request.get_json(silent=True) or {}
    protocol = data.get("protocol", "oidc")
    source = data.get("source", "manual")  # "session" or "manual"
    preset_key = data.get("preset")

    # Build the profile: start from preset, then overlay user overrides
    if preset_key and preset_key in PRESETS:
        profile = dict(PRESETS[preset_key])
    else:
        profile = {}

    # Allow user overrides on top of preset
    for field in ("required_claims", "optional_claims", "expected_values",
                  "claim_patterns", "required_groups", "required_roles",
                  "nameid_format", "expected_issuer", "expected_audience", "guidance"):
        if field in data:
            profile[field] = data[field]

    # Get claims either from session or from request body
    if source == "session":
        if protocol == "oidc":
            sess = session.get("oidc")
            if not sess:
                return jsonify({"error": "No OIDC session. Login via /oidc/login first."}), 400
            claims = sess.get("claims", {})
        else:
            sess = session.get("saml_user")
            if not sess:
                return jsonify({"error": "No SAML session. Login via /saml/login first."}), 400
            attrs = sess.get("attributes", {})
            claims = {}
            for k, v in attrs.items():
                claims[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
            if sess.get("nameid"):
                claims["_nameid"] = sess["nameid"]
            details = sess.get("assertion_details", {})
            if details.get("nameid_format"):
                claims["_nameid_format"] = details["nameid_format"]
    else:
        claims = data.get("claims", {})

    if not claims:
        return jsonify({"error": "No claims provided and no active session found."}), 400

    if not profile.get("required_claims") and not profile.get("optional_claims"):
        return jsonify({"error": "No checks defined. Select a preset or add required_claims."}), 400

    results = validate_profile(protocol, claims, profile)

    summary = {
        "total": len(results),
        "pass": sum(1 for r in results if r["status"] == "pass"),
        "fail": sum(1 for r in results if r["status"] == "fail"),
        "warn": sum(1 for r in results if r["status"] == "warn"),
    }

    return jsonify({
        "protocol": protocol,
        "source": source,
        "preset": preset_key,
        "summary": summary,
        "results": results,
        "claims_checked": claims,
    })


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@bp.get("/ui")
def ui():
    html = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Integration Checker &bull; Entra Protocol Lab</title>
<link rel="stylesheet" href="/static/css/app.css">
<style>
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media(max-width:800px){ .row { grid-template-columns:1fr; } }
.card { border:1px solid #e5e7eb; border-radius:12px; padding:16px; }
label { display:block; margin-top:10px; font-weight:600; font-size:14px; }
select,input,textarea { width:100%; padding:6px 8px; border:1px solid #d1d5db; border-radius:8px; margin-top:4px; font-size:14px; box-sizing:border-box; }
textarea { height:120px; font-family:ui-monospace,monospace; font-size:13px; }
button { padding:8px 16px; border-radius:8px; border:1px solid #e5e7eb; background:#111827; color:#fff; cursor:pointer; margin-top:12px; font-size:14px; }
button:hover { background:#374151; }
button.secondary { background:#fff; color:#111827; border:1px solid #d1d5db; }
button.secondary:hover { background:#f3f4f6; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:13px; font-weight:600; }
.pass { background:#d1fae5; color:#065f46; }
.fail { background:#fee2e2; color:#991b1b; }
.warn { background:#fef3c7; color:#92400e; }
.check-row { display:flex; align-items:flex-start; gap:10px; padding:8px 0; border-bottom:1px solid #f3f4f6; }
.check-row:last-child { border-bottom:none; }
.check-label { font-weight:600; min-width:180px; font-size:14px; }
.check-msg { flex:1; font-size:14px; }
.guidance { margin-top:4px; padding:8px 12px; background:#eff6ff; border-left:3px solid #3b82f6; border-radius:0 8px 8px 0; font-size:13px; color:#1e40af; }
.summary-bar { display:flex; gap:12px; margin-bottom:16px; }
.tag-list { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
.tag { display:inline-flex; align-items:center; gap:4px; background:#f3f4f6; border:1px solid #d1d5db; border-radius:6px; padding:2px 8px; font-size:13px; }
.tag button { margin:0; padding:0 2px; background:none; color:#991b1b; border:none; font-size:16px; cursor:pointer; }
.add-row { display:flex; gap:6px; margin-top:6px; }
.add-row input { flex:1; margin:0; }
.add-row button { margin:0; padding:4px 10px; font-size:13px; }
pre { background:#111827; color:#e5e7eb; border-radius:8px; padding:12px; overflow:auto; font-size:13px; }
h3 { margin:16px 0 8px; }
.desc { color:#6b7280; font-size:13px; margin-top:2px; }
#results-panel { display:none; }
</style>
</head><body>
<nav style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
  <a href="/">Home</a>
  <a href="/oidc/login?next=/tools/integration/ui">OIDC Login</a>
  <a href="/saml/login?next=/tools/integration/ui">SAML Login</a>
  <a href="/oidc/user">OIDC User</a>
  <a href="/saml/user">SAML User</a>
  <a href="/tools/jwt/ui">JWT Validator</a>
</nav>
<h1>Integration Checker</h1>
<p>Validate your Entra OIDC/SAML token against what a target application expects.
Pick a preset or define custom checks, then validate against your session or pasted claims.</p>
<hr>

<div class="row">
  <!-- LEFT: Configuration -->
  <div class="card">
    <label>Protocol</label>
    <select id="protocol">
      <option value="oidc">OIDC</option>
      <option value="saml">SAML</option>
    </select>

    <label>Preset</label>
    <select id="preset">
      <option value="">— Custom (no preset) —</option>
    </select>
    <div id="preset-desc" class="desc"></div>

    <label>Claims Source</label>
    <select id="source">
      <option value="session">From current session (login first)</option>
      <option value="manual">Paste claims JSON manually</option>
    </select>

    <div id="manual-input" style="display:none">
      <label>Claims JSON</label>
      <textarea id="claims-json" placeholder='{"email":"john@contoso.com","name":"John Doe",...}'></textarea>
    </div>

    <hr style="margin:16px 0">
    <h3>Check Configuration</h3>

    <label>Required Claims</label>
    <div id="req-claims-list" class="tag-list"></div>
    <div class="add-row">
      <input id="req-claim-input" placeholder="e.g. email or full SAML URI">
      <button type="button" class="secondary" data-add="req-claims">Add</button>
    </div>

    <label>Optional Claims</label>
    <div id="opt-claims-list" class="tag-list"></div>
    <div class="add-row">
      <input id="opt-claim-input" placeholder="e.g. groups">
      <button type="button" class="secondary" data-add="opt-claims">Add</button>
    </div>

    <label>Expected Values <span style="font-weight:normal;color:#6b7280">(claim=value)</span></label>
    <div id="exp-values-list" class="tag-list"></div>
    <div class="add-row">
      <input id="exp-values-input" placeholder="e.g. aud=abc-123-def">
      <button type="button" class="secondary" data-add="exp-values">Add</button>
    </div>

    <label>Required Groups <span style="font-weight:normal;color:#6b7280">(group ID or name)</span></label>
    <div id="req-groups-list" class="tag-list"></div>
    <div class="add-row">
      <input id="req-groups-input" placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000">
      <button type="button" class="secondary" data-add="req-groups">Add</button>
    </div>

    <label>Required Roles</label>
    <div id="req-roles-list" class="tag-list"></div>
    <div class="add-row">
      <input id="req-roles-input" placeholder="e.g. Admin">
      <button type="button" class="secondary" data-add="req-roles">Add</button>
    </div>

    <label>Expected NameID Format <span style="font-weight:normal;color:#6b7280">(SAML only)</span></label>
    <input id="nameid-format" placeholder="e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">

    <label>Expected Issuer <span style="font-weight:normal;color:#6b7280">(OIDC only)</span></label>
    <input id="expected-issuer" placeholder="e.g. https://login.microsoftonline.com/{tenant}/v2.0">

    <label>Expected Audience <span style="font-weight:normal;color:#6b7280">(OIDC only)</span></label>
    <input id="expected-audience" placeholder="e.g. your-client-id">

    <button id="btn-validate" type="button">Validate</button>
  </div>

  <!-- RIGHT: Results -->
  <div>
    <div class="card" id="results-panel">
      <h2 style="margin-top:0">Results</h2>
      <div id="summary" class="summary-bar"></div>
      <div id="checks"></div>
      <h3>Claims Received</h3>
      <pre id="claims-output"></pre>
    </div>
    <div class="card" id="empty-panel">
      <p style="color:#6b7280;text-align:center;padding:40px 0">
        Configure your checks on the left and click <b>Validate</b> to see results here.
      </p>
    </div>
  </div>
</div>

<script src="/static/js/integration-ui.js"></script>
</body></html>
"""
    return render_template_string(html)
