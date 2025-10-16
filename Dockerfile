# ---------- Builder ----------
FROM python:3.14-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Build toolchain + headers for lxml/xmlsec builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential gcc pkg-config \
    libxml2-dev libxslt1-dev zlib1g-dev \
    libxmlsec1-dev libxmlsec1-openssl \
    libffi-dev openssl \
  && rm -rf /var/lib/apt/lists/*

# Install uv (into /root/.local/bin)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh -s --
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

# Copy only metadata first to maximize layer cache
COPY pyproject.toml uv.lock ./

# Create venv and install deps exactly as locked, targeting the active venv
RUN uv venv /opt/venv \
 && . /opt/venv/bin/activate \
 && uv sync --frozen --active

# ---------- Runtime ----------
FROM python:3.14-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Runtime libs only (no compilers/headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    libxml2 libxslt1.1 zlib1g \
    libxmlsec1 libxmlsec1-openssl xmlsec1 \
    openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring in the ready virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Now add your source code
COPY . .

ENV PORT=3000
EXPOSE 3000

# Dev-friendly gunicorn command (bumped timeout + threads)
CMD ["gunicorn","-w","2","-t","120","-k","gthread","--threads","4","-b","0.0.0.0:3000","wsgi:app"]
