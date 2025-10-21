import os, socket
from urllib.parse import urlparse
from werkzeug.middleware.proxy_fix import ProxyFix
from app import create_app
from app.config import settings


app = create_app() 

@app.get("/__routes")
def __routes():
    lines = []
    for rule in app.url_map.iter_rules():
        methods = ",".join(sorted(rule.methods - {"HEAD","OPTIONS"}))
        lines.append(f"{methods:7s} {rule.rule} -> {rule.endpoint}")
    lines.sort()
    return "<pre>" + "\n".join(lines) + "</pre>"

if os.getenv("TRUST_PROXY", "1") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

def _desired_host_port():
    base = os.getenv("BASE_URL", "http://localhost:3000")
    u = urlparse(base)
    scheme = u.scheme or "http"
    public_host = u.hostname or "localhost"
    public_port = u.port or (443 if scheme == "https" else 3000)
    # Bind 127.0.0.1 for localhost; otherwise bind all interfaces so reverse proxy can reach us
    bind_host = os.getenv("HOST") or ("127.0.0.1" if public_host in ("localhost", "127.0.0.1") else "0.0.0.0")
    port = int(os.getenv("PORT") or public_port)
    return bind_host, port, scheme, public_host, public_port

if __name__ == "__main__":
    bind_host, port, scheme, public_host, public_port = _desired_host_port()

    # Friendly print of the URL people should open
    external_url = os.getenv("BASE_URL", f"{scheme}://{public_host}:{public_port}")
    print(f" * Open {external_url}")
    if bind_host == "0.0.0.0":
        try:
            ip = socket.gethostbyname(socket.gethostname())
            print(f" * Also reachable on http://{ip}:{port}")
        except Exception:
            pass

    app.run(host=bind_host, port=port)