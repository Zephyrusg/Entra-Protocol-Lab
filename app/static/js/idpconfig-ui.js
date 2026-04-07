(function () {
    "use strict";

    // ── IDP presets (metadata URL patterns) ──
    var PRESETS = {
        entra: {
            hint: "Set your Tenant ID in the metadata URL below.",
            oidcMeta: "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration",
            samlMeta: "https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml?appid={app-id}",
        },
        google: {
            hint: "Google only supports OIDC (no SAML metadata URL).",
            oidcMeta: "https://accounts.google.com/.well-known/openid-configuration",
            samlMeta: "",
        },
        okta: {
            hint: "Replace {your-domain} with your Okta org domain.",
            oidcMeta: "https://{your-domain}.okta.com/.well-known/openid-configuration",
            samlMeta: "https://{your-domain}.okta.com/app/{app-id}/sso/saml/metadata",
        },
        auth0: {
            hint: "Replace {your-tenant} with your Auth0 tenant name.",
            oidcMeta: "https://{your-tenant}.auth0.com/.well-known/openid-configuration",
            samlMeta: "https://{your-tenant}.auth0.com/samlp/metadata/{client-id}",
        },
        keycloak: {
            hint: "Replace {host} and {realm} with your Keycloak values.",
            oidcMeta: "https://{host}/realms/{realm}/.well-known/openid-configuration",
            samlMeta: "https://{host}/realms/{realm}/protocol/saml/descriptor",
        },
        custom: {
            hint: "Fill in the URLs for your custom IDP.",
            oidcMeta: "",
            samlMeta: "",
        },
    };

    var TEXT_FIELDS = [
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "OIDC_METADATA_URL",
        "OIDC_REDIRECT_URI",
        "OIDC_SCOPES",
        "SAML_SP_ENTITY_ID",
        "SAML_IDP_METADATA_URL",
    ];

    // ── Helpers ──

    function $(id) { return document.getElementById(id); }

    function showStatus(msg, ok) {
        var el = $("status");
        el.textContent = msg;
        el.className = ok ? "success" : "error";
        if (ok) setTimeout(function () { el.className = ""; }, 4000);
    }

    function loadCurrent() {
        fetch("/tools/idpconfig/current")
            .then(function (r) { return r.json(); })
            .then(function (data) { populateForm(data); })
            .catch(function (e) { showStatus("Failed to load settings: " + e, false); });
    }

    function populateForm(data) {
        TEXT_FIELDS.forEach(function (key) {
            var el = $(key);
            if (el && data[key] !== undefined) el.value = data[key];
        });
        var cb = $("SAML_SIGN_REQUEST");
        if (cb) cb.checked = !!data["SAML_SIGN_REQUEST"];
    }

    function gatherForm() {
        var body = {};
        TEXT_FIELDS.forEach(function (key) {
            var el = $(key);
            if (el) body[key] = el.value;
        });
        var cb = $("SAML_SIGN_REQUEST");
        if (cb) body["SAML_SIGN_REQUEST"] = cb.checked;
        return body;
    }

    // ── Preset selector ──
    function onPresetChange() {
        var key = $("idp-preset").value;
        var preset = PRESETS[key];
        var hint = $("preset-hint");
        if (!preset) { hint.textContent = ""; return; }
        hint.textContent = preset.hint;
        if (preset.oidcMeta) $("OIDC_METADATA_URL").value = preset.oidcMeta;
        if (preset.samlMeta !== undefined) $("SAML_IDP_METADATA_URL").value = preset.samlMeta;
    }

    // ── Secret toggle ──
    function initSecretToggles() {
        document.querySelectorAll(".secret-toggle").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var input = $(btn.getAttribute("data-target"));
                if (!input) return;
                if (input.type === "password") {
                    input.type = "text";
                    btn.textContent = "hide";
                } else {
                    input.type = "password";
                    btn.textContent = "show";
                }
            });
        });
    }

    // ── Apply / Reset ──
    function applySettings() {
        $("apply-btn").disabled = true;
        fetch("/tools/idpconfig/apply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(gatherForm()),
        })
            .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
            .then(function (res) {
                if (res.data.ok) {
                    showStatus("Settings applied. OIDC client re-initialized.", true);
                    populateForm(res.data.settings);
                } else {
                    showStatus("Error: " + (res.data.error || "Unknown error"), false);
                }
            })
            .catch(function (e) { showStatus("Request failed: " + e, false); })
            .finally(function () { $("apply-btn").disabled = false; });
    }

    function resetSettings() {
        if (!confirm("Reset all IDP settings to the original .env / default values?")) return;
        $("reset-btn").disabled = true;
        fetch("/tools/idpconfig/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.ok) {
                    showStatus("Settings reset to env defaults.", true);
                    populateForm(data.settings);
                    $("idp-preset").value = "";
                    $("preset-hint").textContent = "";
                } else {
                    showStatus("Error: " + (data.error || "Unknown error"), false);
                }
            })
            .catch(function (e) { showStatus("Request failed: " + e, false); })
            .finally(function () { $("reset-btn").disabled = false; });
    }

    // ── Init ──
    document.addEventListener("DOMContentLoaded", function () {
        loadCurrent();
        initSecretToggles();
        $("idp-preset").addEventListener("change", onPresetChange);
        $("apply-btn").addEventListener("click", applySettings);
        $("reset-btn").addEventListener("click", resetSettings);
    });
})();
