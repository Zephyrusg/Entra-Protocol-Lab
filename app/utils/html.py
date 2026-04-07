DEFAULT_LINKS = [
    ("Home", "/"),
    ("OIDC Login", "/oidc/login"),
    ("OIDC User", "/oidc/user"),
    ("SAML Login", "/saml/login"),
    ("SAML User", "/saml/user"),
    ("SAML Metadata", "/saml/metadata"),
    ("IDP Config", "/tools/idpconfig/ui"),
]

def page(title: str, body: str, *, show_nav: bool = True, links=DEFAULT_LINKS) -> str:
    nav_html = ""
    if show_nav and links:
        nav_html = " | ".join(f"<a href='{href}'>{text}</a>" for text, href in links)
        nav_html = f"<nav id='top-nav'>{nav_html} | <button id='theme-toggle' class='theme-toggle'></button></nav><hr/>"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/app.css">
<script src="/static/js/theme.js"></script>
<title>{title}</title></head>
<body>
<h1>{title}</h1>
{nav_html}
{body}
</body></html>"""

def pretty_json(obj) -> str:
    import json, re
    raw = json.dumps(obj, indent=2, sort_keys=True, default=str)
    # Highlight empty / null values so they stand out
    raw = re.sub(
        r': (null|""\s*|"\s+")',
        lambda m: ': <span class="empty-val">' + m.group(1).strip() + " \u26a0 empty</span>",
        raw,
    )
    return raw

def redact(value: str, head: int = 4, tail: int = 4, mask_char: str = "•") -> str:
    if not value:
        return ""
    n = len(value)
    if n <= head + tail:
        return mask_char * n
    return value[:head] + (mask_char * (n - head - tail)) + value[-tail:]