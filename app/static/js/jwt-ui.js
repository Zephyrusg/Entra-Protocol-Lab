(() => {
  const $ = (id) => document.getElementById(id);
  const btn = $("btn");

  function badge(txt, okOrClass) {
    const cls = typeof okOrClass === "string" ? okOrClass : (okOrClass ? "ok" : "fail");
    return `<span class="badge ${cls}">${txt}</span>`;
  }

  btn.type = "button";
  btn.addEventListener("click", async () => {
    const statusEl = $("status"), hdrEl = $("hdr"), claimsEl = $("claims"), rawEl = $("raw");
    statusEl.innerHTML = "Validating…";
    hdrEl.textContent = claimsEl.textContent = rawEl.textContent = "";

    const body = {
      token: $("token").value.trim(),
      authority: $("authority").value.trim() || undefined,
      expected_aud: $("aud").value.trim() || undefined,
    };
    if (!body.token) {
      statusEl.innerHTML = `<span class="badge fail">No token provided</span>`;
      return;
    }

    try {
      const res = await fetch("/tools/jwt/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();

      statusEl.innerHTML = [
        badge(`sig:${!!data.sig_ok}`, !!data.sig_ok),
        badge(`iss:${!!data.iss_ok}`, !!data.iss_ok),
        badge(`aud:${!!data.aud_ok}`, !!data.aud_ok),
        badge(`exp:${!!data.exp_ok}`, !!data.exp_ok),
        badge(`nbf:${!!data.nbf_ok}`, !!data.nbf_ok),
        (data.warnings && data.warnings.length)
          ? badge(`warn:${data.warnings.length}`, "warn")
          : badge("warn:0", "ok"),
      ].join(" ");

      hdrEl.textContent = JSON.stringify(data.header || {}, null, 2);
      claimsEl.textContent = JSON.stringify(data.claims || {}, null, 2);
      rawEl.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      statusEl.innerHTML = `<span class="badge fail">Request failed</span>`;
      rawEl.textContent = String(err);
    }
  });
})();
