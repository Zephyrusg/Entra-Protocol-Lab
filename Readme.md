# Entra Protocol Lab

A Flask web application for testing and debugging **SAML** and **OIDC** authentication flows with Microsoft Entra ID (formerly Azure AD). This tool helps developers understand authentication protocols by providing a clear view of tokens, claims, and responses from Entra.

## Features

- 🔐 **OIDC Authentication**: Test OpenID Connect flows with Entra ID
- 🎫 **SAML Authentication**: Test SAML 2.0 flows with Entra Enterprise Applications
- 🔍 **Token Inspection**: View and debug ID tokens, access tokens, and SAML assertions
- 🌐 **Multiple Environments**: Support for local development and deployed environments
- 📋 **Response Analysis**: Pretty-printed JSON for easy debugging

## Quick Start

### Prerequisites

- Python 3.14+
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
   # Using uv (recommended)
   uv sync
   
   # Or using pip
   pip install -r requirements.txt
   ```

3. **Configure environment variables**

   Create a `.env.local` file in the project root (this file is gitignored):

   ```bash
   # App Configuration
   PORT=3000
   BASE_URL=http://localhost:3000
   SESSION_SECRET=your-secure-session-secret-here
   
   # OIDC (Entra ID App Registration)
   TENANT_ID=your-tenant-id
   OIDC_CLIENT_ID=your-oidc-client-id
   OIDC_CLIENT_SECRET=your-oidc-client-secret
   OIDC_REDIRECT_URI=http://localhost:3000/oidc/callback
   
   # SAML (Entra Enterprise Application)
   SAML_SP_ENTITY_ID=urn:entra-protocol-lab:sp
   SAML_APP_ID=your-saml-app-id
   XMLSEC_BINARY=/usr/bin/xmlsec1
   SHOW_FULL_COOKIES=1
   ```

4. **Run the application**

   ```bash
   # Using uv
   uv run python run.py
   
   # Or directly with Python
   python run.py
   ```

5. **Access the application**

   Open <http://localhost:3000> in your browser

## Configuration

### Entra ID Setup

#### OIDC Application Registration

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Create a new registration:
   - **Name**: Entra Protocol Lab OIDC
   - **Redirect URI**: `http://localhost:3000/oidc/callback`
3. Note the **Application (client) ID** and **Directory (tenant) ID**
4. Create a **client secret** in **Certificates & secrets**

#### SAML Enterprise Application

1. Go to **Azure Portal** → **Microsoft Entra ID** → **Enterprise applications**
2. Create a new application:
   - **Name**: Entra Protocol Lab SAML
   - **Identifier (Entity ID)**: `urn:entra-protocol-lab:sp`
   - **Reply URL**: `http://localhost:3000/saml/acs`
3. Configure SAML settings and note the **Application ID**

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | Application port | Yes |
| `BASE_URL` | Public base URL of your app | Yes |
| `SESSION_SECRET` | Secret for session encryption | Yes |
| `TENANT_ID` | Microsoft Entra tenant ID | Yes |
| `OIDC_CLIENT_ID` | OIDC application client ID | Yes |
| `OIDC_CLIENT_SECRET` | OIDC application client secret | Yes |
| `OIDC_REDIRECT_URI` | OIDC callback URL | Yes |
| `SAML_SP_ENTITY_ID` | SAML Service Provider entity ID | Yes |
| `SAML_APP_ID` | SAML Enterprise Application ID | Yes |
| `XMLSEC_BINARY` | Path to xmlsec1 binary | No |
| `SHOW_FULL_COOKIES` | Show full cookie values in debug | No |

## Usage

### Testing OIDC Flow

1. Navigate to `/oidc/login`
2. Complete the Entra ID authentication
3. View the ID token claims and token details at `/oidc/user`

### Testing SAML Flow

1. Navigate to `/saml/login`
2. Complete the Entra ID SAML authentication
3. View the SAML assertion and user attributes at `/saml/user`

### Available Endpoints

- `/` - Home page with navigation
- `/oidc/login` - Initiate OIDC login
- `/oidc/callback` - OIDC callback endpoint
- `/oidc/user` - View OIDC user info and tokens
- `/oidc/logout` - OIDC logout
- `/saml/login` - Initiate SAML login
- `/saml/acs` - SAML Assertion Consumer Service
- `/saml/user` - View SAML user info and assertions
- `/saml/metadata` - SAML SP metadata
- `/saml/logout` - SAML logout

## Docker Support

Build and run with Docker:

```bash
# Build the image
docker build -t entra-protocol-lab .

# Run with environment file
docker run -p 3000:3000 --env-file .env.local entra-protocol-lab
```

## Development

### Project Structure

```text
entra-protocol-lab/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Configuration management
│   ├── oidc/                # OIDC implementation
│   │   ├── client.py        # OAuth client setup
│   │   └── routes.py        # OIDC endpoints
│   ├── saml/                # SAML implementation
│   │   ├── routes.py        # SAML endpoints
│   │   ├── settings.py      # SAML configuration
│   │   └── types.py         # Type definitions
│   └── utils/               # Shared utilities
│       ├── crypto.py        # PKCE helpers
│       └── html.py          # HTML templates
├── run.py                   # Development server
├── wsgi.py                  # Production WSGI entry point
└── .env.local              # Environment configuration (create this)
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all folders have `__init__.py` files
2. **SAML Signature Issues**: Check `XMLSEC_BINARY` path
3. **Redirect URI Mismatch**: Ensure URLs match between Entra and `.env.local`
4. **Session Issues**: Generate a strong `SESSION_SECRET`

### Debug Mode

Set `FLASK_DEBUG=1` for detailed error messages and auto-reload during development.

## License

This project is for educational and testing purposes.
