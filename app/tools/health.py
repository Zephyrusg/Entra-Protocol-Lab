from __future__ import annotations
import base64, os, time, datetime as dt
from typing import Dict, Any, Tuple, List
from ..config import settings
import requests
from flask import Blueprint, jsonify, request, render_template_string
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET
from ..utils.html import page  # optional, only if you want consistent site chrome
from cryptography.hazmat.primitives import hashes
from email.utils import parsedate_to_datetime
from collections import Counter


bp = Blueprint("tools_health", __name__, url_prefix="/tools/health")

HTTP_TIMEOUT = 6
DEFAULT_OIDC_AUTHORITY = os.getenv("OIDC_AUTHORITY", "https://login.microsoftonline.com/common/v2.0")
SAML_IDP_METADATA_URL = os.getenv("SAML_IDP_METADATA_URL")


def _get_json(url: str) -> Tuple[dict, dict, float]:
    t0 = time.perf_counter(); resp = requests.get(url, timeout=HTTP_TIMEOUT); lat=(time.perf_counter()-t0)*1000; resp.raise_for_status(); return resp.json(), resp.headers, lat

def _fetch_json_with_headers(url: str) -> Tuple[dict, dict, float]:
    t0 = time.perf_counter(); resp = requests.get(url, timeout=HTTP_TIMEOUT); lat=(time.perf_counter()-t0)*1000; resp.raise_for_status(); return resp.json(), resp.headers, lat

def _saml_checks(metadata_url: str) -> tuple[str, dict]:
    status = "ok"
    checks: Dict[str, Any] = {}

    # fetch metadata
    t0 = time.perf_counter()
    resp = requests.get(metadata_url, timeout=HTTP_TIMEOUT)
    latency_ms = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    xml = resp.content
    checks["fetch"] = {"ok": True, "latency_ms": round(latency_ms, 1)}

    # parse basics
    root = ET.fromstring(xml)
    ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
    entity_id = root.attrib.get("entityID")
    sso = [
        {"Binding": el.attrib.get("Binding"), "Location": el.attrib.get("Location")}
        for el in root.findall(".//md:IDPSSODescriptor/md:SingleSignOnService", ns)
    ]

    # signing certs
    cert_nodes = root.findall(".//md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']//ds:X509Certificate", ns)
    certs, any_warn, soon = [], False, 30
    now_utc = dt.datetime.now(dt.timezone.utc)

    for cn in cert_nodes:
        b64 = (cn.text or "").replace("\n", " ").strip().replace(" ", "")
        try:
            der = base64.b64decode(b64)
            cert = x509.load_der_x509_certificate(der, default_backend())

            # UTC-safe properties (no deprecation warning)
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
            days = (na - now_utc).days

            # Public key + signature details
            pk = cert.public_key()
            key_bits = getattr(pk, "key_size", None)
            pk_cls = type(pk).__name__
            if "RSA" in pk_cls:
                pk_alg = "RSA"
            elif "EllipticCurve" in pk_cls:
                pk_alg = "EC"
            else:
                pk_alg = pk_cls

            sig_hash = getattr(cert.signature_hash_algorithm, "name", "unknown")

            # Thumbprints and serial
            sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
            sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
            serial_hex = format(cert.serial_number, "X")  # uppercase hex

            info = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": nb.isoformat().replace("+00:00", "Z"),
                "not_after":  na.isoformat().replace("+00:00", "Z"),
                "days_left": days,
                "serial_hex": serial_hex,
                "thumbprint_sha1": sha1,
                "thumbprint_sha256": sha256,
                "pubkey_alg": pk_alg,
                "key_bits": key_bits,
                "sig_hash": sig_hash,
            }

            if days < 0:
                info["ok"] = False
                info["warning"] = "Expired signing cert"
                any_warn = True
            elif days <= soon:
                info["ok"] = True
                info["warning"] = f"Signing cert expires in {days} days"
                any_warn = True
            else:
                info["ok"] = True

            certs.append(info)

        except Exception:
            certs.append({"ok": False, "warning": "Could not parse signing certificate"})
            any_warn = True

    checks["entity_id"] = entity_id
    checks["sso_endpoints"] = sso
    checks["signing_certs"] = certs
    if any_warn and status == "ok":
        status = "warn"

    return status, checks

def _oidc_checks(authority: str) -> tuple[str, dict]:
    authority = authority.rstrip("/")
    status = "ok"
    checks: Dict[str, Any] = {}

    # Discovery
    t0 = time.perf_counter()
    resp = requests.get(f"{authority}/.well-known/openid-configuration", timeout=HTTP_TIMEOUT)
    lat_ms = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    cfg = resp.json()
    disc = {
        "ok": True,
        "latency_ms": round(lat_ms, 1),
        "issuer": cfg.get("issuer"),
        "authorization_endpoint": cfg.get("authorization_endpoint"),
        "token_endpoint": cfg.get("token_endpoint"),
        "userinfo_endpoint": cfg.get("userinfo_endpoint"),
        "end_session_endpoint": cfg.get("end_session_endpoint"),
        "jwks_uri": cfg.get("jwks_uri"),
        # capabilities (optional, only if present)
        "id_token_signing_alg_values_supported": cfg.get("id_token_signing_alg_values_supported"),
        "token_endpoint_auth_methods_supported": cfg.get("token_endpoint_auth_methods_supported"),
        "response_types_supported": cfg.get("response_types_supported"),
        "scopes_supported": cfg.get("scopes_supported"),
    }
    checks["discovery"] = disc

    # JWKS
    t0 = time.perf_counter()
    r2 = requests.get(disc["jwks_uri"], timeout=HTTP_TIMEOUT)
    lat2 = (time.perf_counter() - t0) * 1000
    r2.raise_for_status()
    jwks = r2.json()
    hdrs = r2.headers
    keys = jwks.get("keys", [])
    checks["jwks"] = {
        "ok": len(keys) > 0,
        "latency_ms": round(lat2, 1),
        "key_count": len(keys),
        "keys": [{"kid": k.get("kid"), "kty": k.get("kty"), "use": k.get("use"), "alg": k.get("alg")} for k in keys],
        "kty_counts": dict(Counter(k.get("kty") for k in keys if k.get("kty"))),
        "alg_counts": dict(Counter(k.get("alg") for k in keys if k.get("alg"))),
    }
    if len(keys) == 0:
        status = "warn"

    # Clock drift
    remote_date = hdrs.get("Date")
    if remote_date:
        remote_ts = parsedate_to_datetime(remote_date)  # tz-aware
        now_utc = dt.datetime.now(dt.timezone.utc)
        drift = int((now_utc - remote_ts.astimezone(dt.timezone.utc)).total_seconds())
        checks["clock"] = {"ok": abs(drift) < 120, "drift_seconds": drift}
        if abs(drift) >= 120 and status == "ok":
            status = "warn"
    else:
        checks["clock"] = {"ok": True, "note": "No Date header; skipping drift check"}

    # if discovery is missing end_session_endpoint, mark as warn (still usable)
    if not disc.get("end_session_endpoint") and status == "ok":
        status = "warn"

    return status, checks

@bp.get("/oidc/ui")
def health_oidc_ui():
    authority = request.args.get("authority") or DEFAULT_OIDC_AUTHORITY
    try:
        status, checks = _oidc_checks(authority)
    except Exception as ex:
        return page("OIDC Health", f"<p style='color:#b91c1c'>Error: {ex}</p>")

    disc = checks["discovery"]
    jwks = checks["jwks"]
    clock = checks.get("clock", {})
    badge = {"ok": "ok", "warn": "warn", "fail": "fail"}.get(status, "warn")

    def fmt_list(items):
        if not items:
            return "<em>n/a</em>"
        return ", ".join(items)

    keys_rows = "".join(
        f"<tr><td><code>{k.get('kid','')}</code></td>"
        f"<td>{k.get('kty','')}</td><td>{k.get('alg','')}</td><td>{k.get('use','')}</td></tr>"
        for k in jwks.get("keys", [])
    ) or "<tr><td colspan='4'><em>No keys</em></td></tr>"

    kty_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in jwks.get("kty_counts", {}).items()) or "<tr><td colspan='2'><em>n/a</em></td></tr>"
    alg_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in jwks.get("alg_counts", {}).items()) or "<tr><td colspan='2'><em>n/a</em></td></tr>"

    html = f"""
<p>Status: <span class="badge {badge}">{status.upper()}</span></p>

<h3>Authority</h3>
<table class="kv">
  <tr><th>Authority</th><td><code>{authority}</code></td></tr>
  <tr><th>Issuer</th><td><code>{disc.get('issuer','')}</code></td></tr>
  <tr><th>Discovery latency</th><td>{disc.get('latency_ms','')} ms</td></tr>
</table>

<h3>Endpoints</h3>
<table class="kv">
  <tr><th>Authorization</th><td><code>{disc.get('authorization_endpoint','')}</code></td></tr>
  <tr><th>Token</th><td><code>{disc.get('token_endpoint','')}</code></td></tr>
  <tr><th>UserInfo</th><td><code>{disc.get('userinfo_endpoint','')}</code></td></tr>
  <tr><th>End Session</th><td><code>{disc.get('end_session_endpoint','') or '<em>not advertised</em>'}</code></td></tr>
  <tr><th>JWKS URI</th><td><code>{disc.get('jwks_uri','')}</code></td></tr>
</table>

<h3>Capabilities</h3>
<table class="kv">
  <tr><th>ID token signing algs</th><td>{fmt_list(disc.get('id_token_signing_alg_values_supported'))}</td></tr>
  <tr><th>Token endpoint auth</th><td>{fmt_list(disc.get('token_endpoint_auth_methods_supported'))}</td></tr>
  <tr><th>Response types</th><td>{fmt_list(disc.get('response_types_supported'))}</td></tr>
  <tr><th>Scopes</th><td>{fmt_list(disc.get('scopes_supported'))}</td></tr>
</table>

<h3>JWKS</h3>
<table class="kv">
  <tr><th>Key Count</th><td>{jwks.get('key_count','')}</td></tr>
  <tr><th>JWKS latency</th><td>{jwks.get('latency_ms','')} ms</td></tr>
</table>

<div class="gridwrap">
  <div>
    <h4>Keys</h4>
    <table class="grid">
      <thead><tr><th>kid</th><th>kty</th><th>alg</th><th>use</th></tr></thead>
      <tbody>{keys_rows}</tbody>
    </table>
  </div>
  <div>
    <h4>Key Stats</h4>
    <table class="grid small"><thead><tr><th>kty</th><th>count</th></tr></thead><tbody>{kty_rows}</tbody></table>
    <table class="grid small"><thead><tr><th>alg</th><th>count</th></tr></thead><tbody>{alg_rows}</tbody></table>
  </div>
</div>

<h3>Clock</h3>
<table class="kv">
  <tr><th>Drift (s)</th><td>{clock.get('drift_seconds','')}</td></tr>
</table>

<style>
  :root {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:999px; background:#eee; }}
  .ok {{ background:#d1fae5; }} .warn {{ background:#fef3c7; }} .fail {{ background:#fee2e2; }}
  .gridwrap {{ display:grid; grid-template-columns: 2fr 1fr; gap:16px; }}
  table.kv td, table.kv th {{ padding:6px 8px; vertical-align:top; }}
  table.kv th {{ text-align:left; color:#374151; width:220px; }}
  table.grid {{ width:100%; border-collapse:collapse; margin-top:6px; }}
  table.grid.small td, table.grid.small th {{ padding:4px 6px; }}
  table.grid th, table.grid td {{ border:1px solid #e5e7eb; padding:6px 8px; }}
  code {{ background:#f9fafb; padding:2px 4px; border-radius:4px; }}
</style>
"""
    return page("OIDC Health", html)

@bp.get("/oidc")
def health_oidc():
    authority = (request.args.get("authority") or DEFAULT_OIDC_AUTHORITY).rstrip("/")
    status = "ok"; checks: Dict[str, Any] = {}
    try:
        cfg, headers, lat = _get_json(f"{authority}/.well-known/openid-configuration")
        checks["discovery"] = {"ok": True, "latency_ms": round(lat,1), "issuer": cfg.get("issuer")}
    except Exception as ex:
        checks["discovery"] = {"ok": False, "error": str(ex)}; status = "fail"; return jsonify({"status":status, "authority":authority, "checks":checks}), 200
    try:
        jwks_uri = cfg.get("jwks_uri"); jwks, hdrs, lat = _fetch_json_with_headers(jwks_uri)
        cnt = len(jwks.get("keys", [])); checks["jwks"] = {"ok": cnt>0, "key_count": cnt, "latency_ms": round(lat,1)}
        if cnt == 0: status = "warn"
    except Exception as ex:
        checks["jwks"] = {"ok": False, "error": str(ex)}; status = "fail"
    try:
        remote_date = hdrs.get("Date") if hdrs else None
        if remote_date:
            remote_ts = dt.datetime.strptime(remote_date, "%a, %d %b %Y %H:%M:%S %Z"); now = dt.datetime.utcnow(); drift = int((now-remote_ts).total_seconds())
            checks["clock"] = {"ok": abs(drift) < 120, "drift_seconds": drift}
            if abs(drift) >= 120 and status == "ok": status = "warn"
        else:
            checks["clock"] = {"ok": True, "note": "No Date header; skipping drift check"}
    except Exception:
        checks["clock"] = {"ok": True, "note": "Clock check skipped"}
    return jsonify({"status": status, "authority": authority, "checks": checks}), 200

@bp.get("/saml")
def health_saml():
    metadata_url = settings.SAML_IDP_METADATA_URL
    if not metadata_url:
        return jsonify({"status":"fail","error":"Provide metadata_url or set SAML_IDP_METADATA_URL"}), 400

    try:
        status, checks = _saml_checks(metadata_url)
        return jsonify({"status": status, "metadata_url": metadata_url, "checks": checks}), 200
    except Exception as ex:
        return jsonify({"status":"fail","error":str(ex), "metadata_url":metadata_url}), 200

@bp.get("/saml/ui")
def health_saml_ui():
    metadata_url = settings.SAML_IDP_METADATA_URL
    if not metadata_url:
        return page("SAML Health", "<p>Set <code>SAML_IDP_METADATA_URL</code> or pass <code>?metadata_url=...</code>.</p>")

    try:
        status, checks = _saml_checks(metadata_url)
    except Exception as ex:
        return page("SAML Health", f"<p style='color:#b91c1c'>Error: {ex}</p>")

    badge = {"ok": "ok", "warn": "warn", "fail": "fail"}.get(status, "warn")
    entity = checks.get("entity_id") or "n/a"
    sso = checks.get("sso_endpoints", [])
    certs = checks.get("signing_certs", [])

    html = f"""
<p>Status: <span class="badge {badge}">{status.upper()}</span></p>

<h3>Identity Provider</h3>
<table class="kv">
  <tr><th>Metadata URL</th><td><a href="{metadata_url}" target="_blank" rel="noreferrer noopener">{metadata_url}</a></td></tr>
  <tr><th>EntityID</th><td><code>{entity}</code></td></tr>
</table>

<h3>SingleSignOn Services</h3>
<table class="grid">
  <thead><tr><th>Binding</th><th>Location</th></tr></thead>
  <tbody>
    {''.join(f"<tr><td>{row['Binding']}</td><td><code>{row['Location']}</code></td></tr>" for row in sso)}
  </tbody>
</table>

<h3>Signing Certificates</h3>
<table class="grid">
  <thead><tr><th>Subject</th><th>Issuer</th><th>Not Before</th><th>Not After</th><th>Days Left</th><th>Status</th></tr></thead>
  <tbody>
    {''.join(_render_cert_row(c) for c in certs)}
  </tbody>
</table>

<style>
  :root {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:999px; background:#eee; }}
  .ok {{ background:#d1fae5; }}
  .warn {{ background:#fef3c7; }}
  .fail {{ background:#fee2e2; }}
  table.kv td, table.kv th {{ padding:6px 8px; vertical-align:top; }}
  table.kv th {{ text-align:left; color:#374151; width:160px; }}
  table.grid {{ width:100%; border-collapse:collapse; }}
  table.grid th, table.grid td {{ border:1px solid #e5e7eb; padding:6px 8px; }}
  code {{ background:#f9fafb; padding:2px 4px; border-radius:4px; }}
</style>
"""
    # use your site wrapper for consistent look
    return page("SAML Health", html)

def _render_cert_row(c: dict) -> str:
    cls = "ok" if c.get("ok") else "fail"
    note = f" <small>({c['warning']})</small>" if c.get("warning") else ""
    key = f"{c.get('pubkey_alg','')} {c.get('key_bits','') or ''}b / {c.get('sig_hash','')}"
    details = (
        f"<details><summary>Details</summary>"
        f"<div>Serial: <code>{c.get('serial_hex','')}</code></div>"
        f"<div>SHA-1: <code>{c.get('thumbprint_sha1','')}</code></div>"
        f"<div>SHA-256: <code>{c.get('thumbprint_sha256','')}</code></div>"
        f"<div>Key: <code>{key}</code></div>"
        f"</details>"
    )
    return (
        "<tr>"
        f"<td>{c.get('subject','')}{details}</td>"
        f"<td>{c.get('issuer','')}</td>"
        f"<td><code>{c.get('not_before','')}</code></td>"
        f"<td><code>{c.get('not_after','')}</code></td>"
        f"<td>{c.get('days_left','')}</td>"
        f"<td><span class='badge {cls}'>{'OK' if c.get('ok') else 'Issue'}</span>{note}</td>"
        "</tr>"
    )