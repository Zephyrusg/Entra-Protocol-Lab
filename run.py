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

@app.get("/debug/session")
def debug_session():
    session["ping"] = session.get("ping", 0) + 1
    return {"ping": session["ping"]}

if __name__ == "__main__":
     app.run(port=settings.PORT)