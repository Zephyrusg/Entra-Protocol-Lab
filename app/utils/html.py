def page(title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial;margin:2rem;max-width:980px}}
pre{{background:#111;color:#eee;padding:1rem;border-radius:8px;overflow:auto}}
a,button{{font-size:1rem}}
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:.25rem}}
</style></head>
<body>
<h1>{title}</h1>
<nav>
  <a href="/">Home</a> |
  <a href="/oidc/login">OIDC Login</a> |
  <a href="/oidc/user">OIDC User</a> |
  <a href="/saml/login">SAML Login</a> |
  <a href="/saml/user">SAML User</a> |
  <a href="/saml/metadata">SAML Metadata</a>
</nav><hr/>
{body_html}
</body></html>"""

def pretty_json(obj) -> str:
    import json
    return json.dumps(obj, indent=2, sort_keys=True, default=str)

def redact(value: str, head: int = 4, tail: int = 4, mask_char: str = "•") -> str:
    if not value:
        return ""
    n = len(value)
    if n <= head + tail:
        return mask_char * n
    return value[:head] + (mask_char * (n - head - tail)) + value[-tail:]