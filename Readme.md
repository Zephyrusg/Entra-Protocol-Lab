# Entra Protocol Lab

A Flask web application for testing and debugging **SAML** and **OIDC** authentication flows with Microsoft Entra ID (formerly Azure AD) — or any standards-compliant identity provider. This tool helps developers understand authentication protocols by providing a clear view of tokens, claims, and responses.

## Features

- 🔐 **OIDC Authentication**: Test OpenID Connect flows with Entra ID
- 🎫 **SAML Authentication**: Test SAML 2.0 flows with Entra Enterprise Applications
- 🔍 **Token Inspection**: View and debug ID tokens, access tokens, and SAML assertions
- 📋 **Response Analysis**: Pretty-printed JSON for easy debugging
- ✅ **Integration Checker**: Validate claims mapping against application presets (e.g. vCloud Director) with pass/fail/warning results and Entra fix guidance
- 🩺 **Health Checks**: Verify OIDC and SAML endpoint connectivity and configuration
- 🔑 **JWT Validator**: Decode and inspect JWT tokens
- 🔄 **Runtime IDP Configuration**: Switch identity providers on the fly without restarting — connect to Entra, Google, Okta, Auth0, Keycloak, or any custom IDP from a single UI

## Quick Start

### Prerequisites

- Python 3.14
- Microsoft Entra ID tenant
- Registered OIDC application in Entra
- SAML Enterprise Application in Entra (for SAML testing)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd entra-protocol-lab
   ```

2. **Install dependencies**

   ```bash
   # xmlsec1 is required for SAML XML signature verification
   # On Debian/Ubuntu:
   apt update
   apt install -y xmlsec1 ca-certificates curl
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   
   Restart Terminal Session to load UV
   
   ```bash
   # Using uv (recommended)
   uv sync
   ```

3. **Configure environment variables**

   Copy the sample environment file and configure it for your setup:

   ```bash
   cp .sampleEnv .env
   ```

   Edit `.env` with your Entra ID configuration:

   ```bash
   # OIDC_REDIRECT_URI is automatically set to BASE_URL + /oidc/callback
   # PORT is mainly for Docker container port exposure

   # PORT=3000
   BASE_URL="http://localhost:3000"
   SESSION_SECRET="your-secure-session-secret-here"
   TENANT_ID="your-tenant-id"
   OIDC_CLIENT_ID="your-oidc-client-id"
   OIDC_CLIENT_SECRET="your-oidc-client-secret"

   # SAML Configuration
   SAML_SP_ENTITY_ID="urn:entra-protocol-lab:sp"
   SAML_APP_ID="your-saml-app-id"
   SHOW_FULL_COOKIES=1
   ```

   **Note:** `OIDC_REDIRECT_URI` is automatically constructed as `BASE_URL + /oidc/callback` and doesn't need to be set manually.

4. **Run the application**

   ```bash
   # Source environment variables and run
   uv run python run.py
   ```

5. **Access the application**

   Open <http://localhost:3000> in your browser

## Configuration

### Entra ID Setup

#### OIDC Application Registration

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Create a new registration:
   - **Name**: Entra Protocol Lab OIDC
   - **Redirect URI**: `http://localhost:3000/oidc/callback` (or your BASE_URL + /oidc/callback)
3. Note the **Application (client) ID** and **Directory (tenant) ID**
4. Create a **client secret** in **Certificates & secrets**

#### SAML Enterprise Application

1. Go to **Azure Portal** → **Microsoft Entra ID** → **Enterprise applications**
2. Create a new application:
   - **Name**: Entra Protocol Lab SAML
   - **Identifier (Entity ID)**: `urn:entra-protocol-lab:sp`
   - **Reply URL**: `http://localhost:3000/saml/acs` (or your BASE_URL + /saml/acs)
3. Configure SAML settings and note the **Application ID**

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | Container port exposure (mainly for Docker) | No |
| `BASE_URL` | Public base URL of your app | Yes |
| `SESSION_SECRET` | Secret for session encryption | Yes |
| `TENANT_ID` | Microsoft Entra tenant ID | Yes |
| `OIDC_CLIENT_ID` | OIDC application client ID | Yes |
| `OIDC_CLIENT_SECRET` | OIDC application client secret | Yes |
| `OIDC_REDIRECT_URI` | Auto-set to BASE_URL + /oidc/callback | No* |
| `SAML_SP_ENTITY_ID` | SAML Service Provider entity ID | Yes |
| `SAML_APP_ID` | SAML Enterprise Application ID | Yes |
| `SAML_IDP_METADATA_URL` | Custom SAML IDP metadata URL (overrides Entra auto-build) | No |
| `OIDC_METADATA_URL` | Custom OIDC discovery URL (overrides Entra auto-build) | No |
| `OIDC_SCOPES` | OIDC scopes to request (default: `openid profile email`) | No |
| `SHOW_FULL_COOKIES` | Show full cookie values in debug | No |

*\* Automatically constructed from BASE_URL - do not set manually*

## Usage

### Testing OIDC Flow

1. Navigate to `/oidc/login`
2. Complete the Entra ID authentication
3. View the ID token claims and token details at `/oidc/user`

### Testing SAML Flow

1. Navigate to `/saml/login`
2. Complete the Entra ID SAML authentication
3. View the SAML assertion and user attributes at `/saml/user`

### Using the Integration Checker

The Integration Checker validates whether your Entra token contains the claims an application expects.

1. Navigate to `/tools/integration/ui`
2. Select a **Preset** (e.g. *VMware Cloud Director — SAML*) or configure custom checks
3. Choose **Claims Source**: pick *From current session* and login first, or *Paste claims JSON manually*
4. Click **Validate**
5. Review the results — ✅ pass, ❌ fail, ⚠️ warning — each with Entra-specific guidance on how to fix it

> **Tip:** You can login and return directly to the checker using the OIDC/SAML Login links in the navigation bar. The `?next=` parameter redirects you back after authentication.

### Switching Identity Providers at Runtime

The IDP Configuration page lets you point the app at a different identity provider without restarting or editing `.env`.

1. Navigate to `/tools/idpconfig/ui`
2. Optionally pick a **Quick preset** (Entra, Google, Okta, Auth0, Keycloak) to pre-fill the discovery URLs
3. Fill in the **Client ID**, **Client Secret**, and any other fields for your target IDP
4. Click **Apply Changes** — the OIDC client is re-initialized and SAML metadata URL is updated immediately
5. Use the OIDC/SAML Login links to test against the new IDP

> **Note:** Settings are stored **in memory only** and are lost when the app restarts. Use the **Reset to Env Defaults** button to restore the original `.env` values.

### Available Endpoints

#### Main Endpoints
- `/` - Home page with navigation
- `/__routes` - Display all available routes (debug helper)

#### OIDC Endpoints
- `/oidc/login` - Initiate OIDC login (supports `?next=/path` to redirect after login)
- `/oidc/callback` - OIDC callback endpoint
- `/oidc/user` - View OIDC user info and tokens
- `/oidc/logout` - OIDC logout
- `/oidc/ui/logout` - OIDC logout with UI
- `/oidc/logout-url` - Get OIDC logout URL

#### SAML Endpoints
- `/saml/login` - Initiate SAML login (supports `?next=/path` to redirect after login)
- `/saml/acs` - SAML Assertion Consumer Service
- `/saml/acs-complete` - Intermediate redirect after SAML ACS (handles SameSite cookie flow)
- `/saml/user` - View SAML user info and assertions
- `/saml/logout` - SAML logout
- `/saml/logout-url` - Get SAML logout URL
- `/saml/metadata` - SAML SP metadata
- `/saml/debug/config` - Display SAML configuration details

#### Tools - JWT
- `/tools/jwt/ui` - JWT token validation and inspection tool
- `/tools/jwt/validate` - POST endpoint for JWT validation

#### Tools - Integration Checker
- `/tools/integration/ui` - Integration validation UI (check claims against app profiles)
- `/tools/integration/validate` - POST endpoint for integration validation
- `/tools/integration/presets` - List available app presets (vCloud Director, etc.)
- `/tools/integration/session/oidc` - Get OIDC claims from current session
- `/tools/integration/session/saml` - Get SAML attributes from current session

#### Tools - Health Checks
- `/tools/health/oidc` - OIDC health check
- `/tools/health/oidc/ui` - OIDC health check with UI
- `/tools/health/saml` - SAML health check
- `/tools/health/saml/ui` - SAML health check with UI

#### Tools - IDP Configuration
- `/tools/idpconfig/ui` - Runtime IDP configuration page
- `/tools/idpconfig/current` - GET current effective settings
- `/tools/idpconfig/apply` - POST new settings (JSON body)
- `/tools/idpconfig/reset` - POST reset to env defaults

## Docker Support

The application uses the same `.env` file for both local development and Docker deployment.

Build and run with Docker:

```bash
# Build the image
docker build -t entra-protocol-lab .

# Run with environment file
docker run -p 3000:3000 --env-file .env entra-protocol-lab
```

## Development

### Project Structure

```text
entra-protocol-lab/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Configuration management
│   ├── oidc/                # OIDC implementation
│   │   ├── __init__.py      # OIDC module initialization
│   │   ├── client.py        # OAuth client setup
│   │   └── routes.py        # OIDC endpoints
│   ├── saml/                # SAML implementation
│   │   ├── __init__.py      # SAML module initialization
│   │   ├── routes.py        # SAML endpoints
│   │   └── settings.py      # SAML configuration
│   ├── static/              # Static web assets
│   │   ├── css/
│   │   │   └── app.css      # Application styles
│   │   └── js/
│   │       ├── jwt-ui.js    # JWT UI JavaScript
│   │       ├── integration-ui.js  # Integration Checker UI JavaScript
│   │       └── idpconfig-ui.js    # IDP Configuration UI JavaScript
│   ├── templates/           # Jinja2 HTML templates
│   │   ├── integration.html # Integration Checker UI page
│   │   └── idpconfig.html   # IDP Configuration UI page
│   ├── tools/               # Utility tools
│   │   ├── __init__.py      # Tools module initialization
│   │   ├── health.py        # Health check endpoints
│   │   ├── idpconfig.py     # Runtime IDP configuration
│   │   ├── integration.py   # Integration checker (claims validation)
│   │   └── jwt.py           # JWT validation tools
│   └── utils/               # Shared utilities
│       ├── __init__.py      # Utils module initialization
│       ├── crypto.py        # PKCE helpers
│       └── html.py          # HTML helper utilities (page wrapper, pretty_json, redact)
├── Dockerfile              # Docker container configuration
├── pyproject.toml          # Python project configuration
├── Readme.md               # Project documentation
├── .sampleEnv              # Environment template
├── .env                    # Your local config (gitignored — create from .sampleEnv)
├── run.py                 # Development server
└── wsgi.py               # Production WSGI entry point
```

## Troubleshooting

### Common Issues

1. **Redirect URI Mismatch**: Ensure URLs match between Entra and your `.env` file
2. **Session Issues**: Generate a strong `SESSION_SECRET`
3. **SAML fails with cryptic XML error**: Make sure `xmlsec1` is installed (`apt install xmlsec1` or `brew install libxmlsec1` on macOS). Without it, SAML signature verification fails silently.
4. **Cookie / session lost after login**: If running behind a reverse proxy with HTTPS, ensure `BASE_URL` uses `https://`. SameSite cookie behaviour differs between HTTP and HTTPS, which can cause sessions to be dropped on the redirect back from Entra.
5. **Session storage growing**: Sessions are stored as files in `/tmp/flask-sessions` with a 4-hour lifetime. On long-running instances, old files may accumulate. Clean up with `find /tmp/flask-sessions -mtime +1 -delete`.

### Trusting a Custom CA Certificate (e.g. AD FS with Internal PKI)

When connecting to an IDP that uses a certificate signed by an internal/private CA (common with AD FS), the app will fail with an SSL error like `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`. This happens because Python's `requests` library uses its own CA bundle (`certifi`) instead of the OS trust store.

**Step 1 — Obtain the CA certificate**

Export the root (and any intermediate) CA certificate(s) in **Base-64 encoded X.509 (.cer / .pem)** format. On Windows you can do this from the browser certificate viewer or via `certutil`:

```
certutil -encode "CA-Root.cer" ca-root.pem
```

**Step 2 — Add to the OS trust store (Linux / WSL)**

```bash
sudo cp ca-root.pem /usr/local/share/ca-certificates/ca-root.crt
sudo update-ca-certificates
```

Verify with OpenSSL:

```bash
echo | openssl s_client -connect your-idp.example.com:443 -servername your-idp.example.com 2>&1 | head -5
# Should show: verify return:1
```

**Step 3 — Add to Python's certifi bundle**

This project uses **uv** to manage its Python environment. The `requests` library inside the uv-managed virtualenv uses its own CA bundle (`certifi`), which does not include your internal CA by default. Find its location and append the CA cert:

```bash
# Find the bundle path (note: use uv run to execute inside the project venv)
uv run python -c "import certifi; print(certifi.where())"
# Example output: .venv/lib/python3.14/site-packages/certifi/cacert.pem

# Append the CA cert
cat /etc/ssl/certs/ca-root.pem >> $(uv run python -c "import certifi; print(certifi.where())")
```

> **⚠️ Note:** this patch is fragile — running `uv sync`, `uv lock`, or updating the `certifi` package will overwrite the bundle and you will need to append again.

**Permanent alternative** — instead of patching the certifi bundle, set the `REQUESTS_CA_BUNDLE` environment variable to point to the system trust store. Add it to your `.env` file so the app picks it up automatically:

```bash
# .env
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

Or export it in your shell before running the app:

```bash
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
uv run run.py
```

**Step 4 — Verify from Python**

```bash
uv run python -c "import requests; r = requests.get('https://your-idp.example.com/.well-known/openid-configuration', timeout=5); print(r.status_code)"
# Should print: 200
```

> **Tip:** The IDP Configuration page (`/tools/idpconfig/ui`) has a built-in **Test Connection** button that will immediately show whether the SSL handshake succeeds.

### Debug Mode

Set `FLASK_DEBUG=1` for detailed error messages and auto-reload during development.

## License

This project is for educational and testing purposes.
