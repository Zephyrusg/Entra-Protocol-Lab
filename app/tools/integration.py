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

import json, re
from typing import Any, Dict, List

from flask import Blueprint, jsonify, render_template, request, session
from ..utils.html import page

bp = Blueprint("tools_integration", __name__, url_prefix="/tools/integration")


def _flatten_saml_session(saml_data: dict) -> Dict[str, Any]:
    """Flatten SAML session attributes into a simple claim dict."""
    attrs = saml_data.get("attributes", {})
    flat: Dict[str, Any] = {}
    for k, v in attrs.items():
        flat[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
    if saml_data.get("nameid"):
        flat["_nameid"] = saml_data["nameid"]
    details = saml_data.get("assertion_details", {})
    if details.get("nameid_format"):
        flat["_nameid_format"] = details["nameid_format"]
    return flat

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

    # 4. Claim value patterns (regex) — with ReDoS safeguard
    for claim, pattern in profile.get("claim_patterns", {}).items():
        val = _get_claim_value(claims, claim)
        short_name = claim.rsplit("/", 1)[-1] if "/" in claim else claim
        if val is None:
            continue  # already reported in required/optional
        if len(pattern) > 200:
            results.append(_check("fail", f"Pattern: {short_name}",
                                  "Pattern too long (max 200 chars)"))
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            results.append(_check("fail", f"Pattern: {short_name}",
                                  f"Invalid regex pattern: {exc}"))
            continue
        val_str = val if isinstance(val, str) else json.dumps(val, default=str)
        if compiled.search(val_str):
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
    """Return the full list of available presets (including claims/config)."""
    out = {}
    for key, preset in PRESETS.items():
        out[key] = {
            "name": preset["name"],
            "protocol": preset["protocol"],
            "description": preset.get("description", ""),
            "required_claims": preset.get("required_claims", []),
            "optional_claims": preset.get("optional_claims", []),
            "required_groups": preset.get("required_groups", []),
            "required_roles": preset.get("required_roles", []),
            "nameid_format": preset.get("nameid_format") or "",
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
    return jsonify({"claims": _flatten_saml_session(data), "source": "session"})


@bp.route("/validate", methods=["POST"])
def validate_route():
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
            claims = _flatten_saml_session(sess)
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
    return render_template("integration.html")
