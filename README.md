## FastAPI Scalekit Authentication Example

A simple FastAPI app that shows how to add secure sign-in with Scalekit (OIDC). You can use it as a starting point or as a reference to integrate enterprise-grade authentication.

What this example includes:

- The app signs users in with Scalekit using the OpenID Connect (OIDC) authorization flow.
- The `/dashboard` page is protected and redirects unauthenticated users to the login flow.
- The configuration shows how to register an OAuth 2.0 client and wire login, callback, and logout endpoints.
- The templates use Bootstrap classes so pages render well on desktop and mobile.
- After login, the dashboard displays selected ID token claims to demonstrate how to access user information.

### Prerequisites

- Python 3.8 or later is installed.
- pip is installed.
- You have a Scalekit account with an OIDC application. [Sign up](https://app.scalekit.com/)

## 🛠️ Quick start

### Configure Scalekit

Pick one method below.

_Method A_ — .env file (recommended for local dev):

Create or update `.env` in the project root:

```env
# Replace placeholders with your values
SCALEKIT_ENV_URL=https://your-env.scalekit.io
SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
SCALEKIT_REDIRECT_URI=http://localhost:8000/auth/callback

# Optional server config
DEBUG=True
SECRET_KEY=your-secret-key-change-me-in-production
```

_Method B_ — environment variables:

```bash
export SCALEKIT_ENV_URL=https://your-env.scalekit.io
export SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
export SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
export SCALEKIT_REDIRECT_URI=http://localhost:8000/auth/callback
```

Important:

- Never commit secrets to source control.
- Ensure the redirect URI exactly matches what is configured in Scalekit.

### Build and run

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or using Python directly:

```bash
python -m app.main
```

The application will start at `http://localhost:8000`

### Setup Scalekit

To find your required values:

1.  Visit [Scalekit Dashboard](https://app.scalekit.com) and proceed to _Settings_

2.  Copy the API credentials

    - **Environment URL** (e.g., `https://your-env.scalekit.dev`)
    - **Client ID**
    - **Client Secret**

3.  Authentication > Redirect URLs > Allowed redirect URIs:
    - Add `http://localhost:8000/auth/callback` (no trailing slash)
    - Optionally add `http://localhost:8000` as a post-logout redirect

### Application routes

| Route                            | Description                 | Auth required |
| -------------------------------- | --------------------------- | ------------- |
| `/`                              | Home page with login option | No            |
| `/login`                         | Custom login page           | No            |
| `/auth/callback`                 | OIDC callback               | No            |
| `/dashboard`                     | Protected dashboard         | Yes           |
| `/sessions`                      | Session management          | Yes           |
| `/sessions/validate-token`       | Validate token (POST)        | Yes           |
| `/sessions/refresh-token`        | Refresh token (POST)         | Yes           |
| `/organization/settings`          | Protected settings page     | Yes (permission) |
| `/logout`                        | Logout and end session      | Yes           |

### 🚦 Try the app

1. Start the app (see Quick start)
2. Visit `http://localhost:8000`
3. Click Sign in with Scalekit
4. Authenticate with your provider
5. Open the dashboard and then try logout

Stuck? [Contact us](https://docs.scalekit.com/support/contact-us/).

#### Enable debug logging

The application uses Python's standard logging. To enable debug logging, set the `DEBUG` environment variable to `True` in your `.env` file:

```env
DEBUG=True
```

#### Code structure

```
fastapi-scalekit-example/
├── app/                          # Main application package
│   ├── __init__.py
│   ├── main.py                   # FastAPI application entry point
│   ├── config.py                 # Configuration settings
│   ├── routes.py                 # API routes and endpoints
│   ├── scalekit_client.py        # Scalekit OAuth client
│   ├── dependencies.py           # FastAPI dependencies (auth, permissions)
│   └── middleware.py             # Token refresh middleware
├── templates/                    # Jinja2 HTML templates
│   ├── index.html                # Home page
│   ├── login.html                # Login page
│   ├── dashboard.html            # User dashboard
│   ├── sessions.html             # Session management
│   ├── organization_settings.html # Protected settings page
│   ├── error.html                # Error page
│   └── permission_denied.html   # Permission denied page
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variables template
├── .gitignore
└── README.md                     # This file
```

#### Dependencies

- FastAPI 0.104+
- **scalekit-sdk-python** (Official Scalekit Python SDK)
- python-dotenv (for environment variable management)
- jinja2 (for templating)
- uvicorn (ASGI server)
- starlette (web framework, included with FastAPI)

See `requirements.txt` for exact versions.

#### Scalekit SDK Methods Used

This application uses the official Scalekit Python SDK for all authentication operations:

- `ScalekitClient.get_authorization_url()` - Generate OAuth authorization URL
- `ScalekitClient.authenticate_with_code()` - Exchange code for tokens
- `ScalekitClient.validate_access_token_and_get_claims()` - Validate tokens and extract permissions
- `ScalekitClient.refresh_access_token()` - Refresh expired tokens
- `ScalekitClient.get_logout_url()` - Generate logout URL


#### Support

- Read the Scalekit docs: [Documentation](https://docs.scalekit.com).
- Read the FastAPI docs: [Documentation](https://fastapi.tiangolo.com).

#### License 📄

This project is for demonstration and learning. Refer to dependency licenses for production use.

