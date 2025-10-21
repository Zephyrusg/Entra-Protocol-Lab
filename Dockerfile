# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim

# ---- minimal OS deps ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      xmlsec1 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# ---- install uv ----
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \ 
 && /root/.local/bin/uv --version \
 && ln -s /root/.local/bin/uv /usr/local/bin/uv 

# Put the virtualenv in the project directory and on PATH
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
ENV PATH="/app/.venv/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PORT=3000 XMLSEC_BINARY=/usr/bin/xmlsec1

WORKDIR /app

# ---- dependency layer ----
COPY pyproject.toml ./
# COPY uv.lock ./        # (uncomment if you have a lockfile)
RUN uv sync --no-dev

# ---- app layer ----
COPY . .
RUN uv sync --no-dev     # install the project itself into /app/.venv

# ---- non-root user (fixed) ----
RUN groupadd -r appuser \
 && useradd -r -g appuser -m appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 3000

# If you prefer factory, use --factory run:create_app; otherwise use run:app
CMD ["uv","run","gunicorn", \
     "--bind","0.0.0.0:3000", \
     "--workers","2","--threads","4","--timeout","60", \
     "run:app"]
