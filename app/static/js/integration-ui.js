(() => {
    const $ = (id) => document.getElementById(id);

    // ---------------------------------------------------------------------------
    // Tag-list state (arrays of strings)
    // ---------------------------------------------------------------------------
    const tags = {
        "req-claims": [],
        "opt-claims": [],
        "exp-values": [],
        "req-groups": [],
        "req-roles": [],
    };

    function renderTags(key) {
        const list = $(key + "-list");
        list.innerHTML = tags[key]
            .map(
                (t, i) =>
                    `<span class="tag">${esc(t)}<button type="button" class="tag-remove" data-key="${key}" data-idx="${i}">&times;</button></span>`
            )
            .join("");
        // Attach remove listeners
        list.querySelectorAll(".tag-remove").forEach((btn) => {
            btn.addEventListener("click", () => {
                const k = btn.getAttribute("data-key");
                const idx = parseInt(btn.getAttribute("data-idx"), 10);
                tags[k].splice(idx, 1);
                renderTags(k);
            });
        });
    }

    function addTag(key) {
        const input = $(key + "-input");
        const val = input.value.trim();
        if (!val) return;
        tags[key].push(val);
        input.value = "";
        renderTags(key);
    }

    // Attach Add button listeners
    for (const key of Object.keys(tags)) {
        const addBtn = document.querySelector(`[data-add="${key}"]`);
        if (addBtn) {
            addBtn.addEventListener("click", () => addTag(key));
        }
    }

    // Allow Enter key to add tags
    for (const key of Object.keys(tags)) {
        const input = $(key + "-input");
        if (input) {
            input.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    window.addTag(key);
                }
            });
        }
    }

    // ---------------------------------------------------------------------------
    // Presets
    // ---------------------------------------------------------------------------
    let presets = {};

    async function loadPresets() {
        try {
            const res = await fetch("/tools/integration/presets");
            presets = await res.json();
            const sel = $("preset");
            for (const [key, info] of Object.entries(presets)) {
                const opt = document.createElement("option");
                opt.value = key;
                opt.textContent = info.name + " (" + info.protocol.toUpperCase() + ")";
                sel.appendChild(opt);
            }
        } catch (e) {
            console.warn("Could not load presets", e);
        }
    }

    $("preset").addEventListener("change", () => {
        const key = $("preset").value;
        if (!key || !presets[key]) {
            $("preset-desc").textContent = "";
            return;
        }
        const info = presets[key];
        $("preset-desc").textContent = info.description || "";
        $("protocol").value = info.protocol;
        // Load preset details into the form
        loadPresetDetails(key);
    });

    async function loadPresetDetails(key) {
        // Fetch full preset from the presets endpoint — but we already have the
        // summary. For the full required_claims etc., call validate with source=manual
        // and empty claims to get the preset. Instead, hardcode from our known presets.
        // Better: fetch from a dedicated endpoint. For now, we can use the preset key
        // and fetch the full config via a small trick: call validate with a dummy
        // and parse the error, or just keep preset details in JS too.
        //
        // Simplest: we embed known preset details by fetching the presets API
        // which only returns summary. So let's load them from the response
        // of /presets which gives name/protocol/description. The actual claim
        // lists come from the server at validate time via the preset key.
        // BUT we want to pre-populate the form so users can see/edit.
        //
        // Solution: We hardcode the most important presets client-side too.
        const PRESET_DETAILS = {
            vcloud_director_saml: {
                required_claims: [
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                ],
                optional_claims: [
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                ],
                nameid_format:
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                expected_issuer: "",
                expected_audience: "",
                required_groups: [],
                required_roles: [],
            },
            vcloud_director_oidc: {
                required_claims: ["email", "name", "preferred_username", "sub"],
                optional_claims: ["groups", "roles"],
                nameid_format: "",
                expected_issuer: "",
                expected_audience: "",
                required_groups: [],
                required_roles: [],
            },
        };

        const details = PRESET_DETAILS[key];
        if (!details) return;

        tags["req-claims"] = [...(details.required_claims || [])];
        tags["opt-claims"] = [...(details.optional_claims || [])];
        tags["exp-values"] = [];
        tags["req-groups"] = [...(details.required_groups || [])];
        tags["req-roles"] = [...(details.required_roles || [])];

        for (const k of Object.keys(tags)) renderTags(k);
        $("nameid-format").value = details.nameid_format || "";
        $("expected-issuer").value = details.expected_issuer || "";
        $("expected-audience").value = details.expected_audience || "";
    }

    // ---------------------------------------------------------------------------
    // Source toggle
    // ---------------------------------------------------------------------------
    $("source").addEventListener("change", () => {
        $("manual-input").style.display =
            $("source").value === "manual" ? "block" : "none";
    });

    // ---------------------------------------------------------------------------
    // Validate
    // ---------------------------------------------------------------------------
    $("btn-validate").addEventListener("click", async () => {
        const protocol = $("protocol").value;
        const source = $("source").value;
        const presetKey = $("preset").value;

        const body = {
            protocol,
            source,
            preset: presetKey || undefined,
            required_claims: tags["req-claims"],
            optional_claims: tags["opt-claims"],
            required_groups: tags["req-groups"],
            required_roles: tags["req-roles"],
            nameid_format: $("nameid-format").value.trim() || undefined,
            expected_issuer: $("expected-issuer").value.trim() || undefined,
            expected_audience: $("expected-audience").value.trim() || undefined,
        };

        // Parse expected values from "key=value" tags
        const ev = {};
        for (const tag of tags["exp-values"]) {
            const eq = tag.indexOf("=");
            if (eq > 0) {
                ev[tag.slice(0, eq).trim()] = tag.slice(eq + 1).trim();
            }
        }
        if (Object.keys(ev).length) body.expected_values = ev;

        // If manual source, parse the JSON
        if (source === "manual") {
            try {
                body.claims = JSON.parse($("claims-json").value);
            } catch (e) {
                alert("Invalid claims JSON: " + e.message);
                return;
            }
        }

        $("btn-validate").textContent = "Validating...";
        $("btn-validate").disabled = true;

        try {
            const res = await fetch("/tools/integration/validate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            const data = await res.json();

            if (data.error) {
                $("empty-panel").innerHTML = `<p style="color:#991b1b;padding:16px"><b>Error:</b> ${esc(data.error)}</p>`;
                $("results-panel").style.display = "none";
                $("empty-panel").style.display = "block";
                return;
            }

            renderResults(data);
        } catch (err) {
            $("empty-panel").innerHTML = `<p style="color:#991b1b;padding:16px"><b>Request failed:</b> ${esc(String(err))}</p>`;
            $("results-panel").style.display = "none";
            $("empty-panel").style.display = "block";
        } finally {
            $("btn-validate").textContent = "Validate";
            $("btn-validate").disabled = false;
        }
    });

    // ---------------------------------------------------------------------------
    // Render results
    // ---------------------------------------------------------------------------
    function renderResults(data) {
        $("results-panel").style.display = "block";
        $("empty-panel").style.display = "none";

        const s = data.summary || {};
        $("summary").innerHTML = [
            `<span class="badge pass">${s.pass || 0} passed</span>`,
            `<span class="badge fail">${s.fail || 0} failed</span>`,
            `<span class="badge warn">${s.warn || 0} warnings</span>`,
            `<span class="badge" style="background:#f3f4f6">${s.total || 0} total</span>`,
        ].join("");

        const checks = data.results || [];
        $("checks").innerHTML = checks
            .map((c) => {
                let guidanceHtml = "";
                if (c.guidance && c.status !== "pass") {
                    guidanceHtml = `<div class="guidance">${esc(c.guidance)}</div>`;
                }
                const icon =
                    c.status === "pass" ? "&#x2705;" : c.status === "fail" ? "&#x274C;" : "&#x26A0;&#xFE0F;";
                return `<div class="check-row">
          <span style="font-size:18px">${icon}</span>
          <span class="check-label">${esc(c.label)}</span>
          <div class="check-msg">
            <span class="badge ${c.status}">${c.status.toUpperCase()}</span>
            ${esc(c.message)}
            ${guidanceHtml}
          </div>
        </div>`;
            })
            .join("");

        $("claims-output").textContent = JSON.stringify(
            data.claims_checked || {},
            null,
            2
        );
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------
    function esc(s) {
        if (!s) return "";
        const d = document.createElement("div");
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }

    // Init
    loadPresets();
})();
