from app import create_app
from app.config import settings


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=settings.PORT, debug=False)