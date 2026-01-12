"""
FastAPI routes for Scalekit authentication and authorization.
Uses session-based storage for authentication state.
"""
import logging
import secrets
from datetime import timedelta, datetime
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from app.scalekit_client import scalekit_client
from app.dependencies import require_login, require_permission
from app.config import settings

logger = logging.getLogger(__name__)

# Initialize templates - use absolute path for reliability
import os
from pathlib import Path

# Get the project root directory (parent of app directory)
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


@router.get("/", response_class=HTMLResponse, name="home_view")
async def home_view(request: Request):
    """
    Home page with login option.
    Route: /
    """
    # If user is already authenticated, redirect to dashboard
    if request.session.get('scalekit_user'):
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/login", response_class=HTMLResponse, name="login_view")
async def login_view(request: Request):
    """
    Custom login page.
    Route: /login
    """
    # If user is already authenticated, redirect to dashboard
    if request.session.get('scalekit_user'):
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    
    # Get authorization URL from Scalekit
    client = scalekit_client()
    auth_url = client.get_authorization_url(state=state)
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "auth_url": auth_url,
    })


@router.get("/auth/callback", response_class=HTMLResponse, name="callback_view")
async def callback_view(request: Request):
    """
    Handle OAuth 2.0 callback from Scalekit.
    Route: /auth/callback
    """
    # Verify state parameter
    state = request.query_params.get('state')
    stored_state = request.session.get('oauth_state')
    
    if not state or state != stored_state:
        logger.error(f"OAuth state mismatch - received: {state}, stored: {stored_state}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Invalid state parameter. Please try logging in again. Make sure cookies are enabled."
        }, status_code=400)
    
    # Clear state from session
    request.session.pop('oauth_state', None)
    
    # Get authorization code
    code = request.query_params.get('code')
    error = request.query_params.get('error')
    
    if error:
        logger.error(f"OAuth error: {error}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": f"Authentication failed: {error}"
        }, status_code=400)
    
    if not code:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "No authorization code received."
        }, status_code=400)
    
    try:
        # Exchange code for tokens
        client = scalekit_client()
        token_response = client.exchange_code_for_tokens(code)
        
        # Extract tokens - try multiple possible key names
        access_token = token_response.get('access_token') or token_response.get('accessToken')
        refresh_token = token_response.get('refresh_token') or token_response.get('refreshToken')
        id_token = token_response.get('id_token') or token_response.get('idToken')
        expires_in = token_response.get('expires_in') or token_response.get('expiresIn') or 3600
        
        # Validate that we have at least an access token
        if not access_token:
            logger.error("No access token received from Scalekit SDK")
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": "Authentication failed: No access token received from Scalekit"
            }, status_code=500)
        
        # Get user object from authenticate_with_code response
        # The SDK's authenticate_with_code already extracts user info from ID token
        user_obj = token_response.get('user', {})
        
        # Get user information from access token for roles and permissions
        try:
            user_info = client.get_user_info(access_token)
        except Exception as e:
            logger.warning(f"Could not get user info from access token: {e}")
            # Use user_obj as fallback
            user_info = user_obj if user_obj else {}
        
        # Map user object fields (camelCase) to our session format (snake_case)
        # user object has: id, name, email, givenName, familyName, username, etc.
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        # Store session data - minimize size to avoid cookie size limits
        # Don't store full claims as they can be decoded from tokens when needed
        request.session['scalekit_user'] = {
            'sub': user_obj.get('id'),
            'email': user_obj.get('email'),
            'name': user_obj.get('name') or f"{user_obj.get('givenName', '')} {user_obj.get('familyName', '')}".strip(),
            'given_name': user_obj.get('givenName'),
            'family_name': user_obj.get('familyName'),
            'preferred_username': user_obj.get('username'),
            # Don't store full claims to reduce cookie size - can be decoded from token
        }
        
        # Store tokens - these are essential
        request.session['scalekit_tokens'] = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'id_token': id_token,
            'expires_at': expires_at.isoformat(),
            'expires_in': expires_in,
        }
        
        # Extract and store roles and permissions (small lists)
        roles = user_info.get('roles', []) or user_info.get('https://scalekit.com/roles', [])
        permissions = user_info.get('permissions', []) or user_info.get('https://scalekit.com/permissions', [])
        request.session['scalekit_roles'] = roles
        request.session['scalekit_permissions'] = permissions
        
        # Clear oauth_state now that we're done with it
        request.session.pop('oauth_state', None)
        
        logger.info(f"User {user_obj.get('email')} authenticated successfully via Scalekit")
        
        # Create redirect response
        # Starlette SessionMiddleware automatically saves session when response is sent
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
        
        return response
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": f"Authentication failed: {str(e)}"
        }, status_code=500)


@router.get("/dashboard", response_class=HTMLResponse, name="dashboard_view")
async def dashboard_view(request: Request, user: dict = Depends(require_login)):
    """
    Protected dashboard page.
    Route: /dashboard
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    roles = request.session.get('scalekit_roles', [])
    permissions = request.session.get('scalekit_permissions', [])
    
    # Get claims from access token (we don't store full claims in session to reduce cookie size)
    # This may refresh the token if it's expired, so we'll update expires_at after
    claims = {}
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')
    
    if access_token:
        try:
            client = scalekit_client()
            claims = client.get_user_info(access_token)
        except Exception as e:
            error_msg = str(e).lower()
            # Check if token expired - try to refresh it
            if ('expired' in error_msg or 'signature has expired' in error_msg) and refresh_token:
                try:
                    # Refresh the token
                    token_response = client.refresh_access_token(refresh_token)
                    
                    # Extract expires_in from JWT or response
                    new_access_token = token_response.get('access_token')
                    expires_in = None
                    
                    # Try to decode JWT to get actual expiry
                    if new_access_token:
                        try:
                            import base64
                            import json
                            parts = new_access_token.split('.')
                            if len(parts) >= 2:
                                payload = parts[1]
                                padding = 4 - len(payload) % 4
                                if padding != 4:
                                    payload += '=' * padding
                                decoded = base64.urlsafe_b64decode(payload)
                                claims_jwt = json.loads(decoded)
                                exp = claims_jwt.get('exp')
                                if exp:
                                    from datetime import timezone
                                    now_ts = datetime.now(timezone.utc).timestamp()
                                    expires_in = int(exp - now_ts)
                        except:
                            expires_in = token_response.get('expires_in') or 3600
                    
                    if not expires_in:
                        expires_in = token_response.get('expires_in') or 3600
                    
                    # Update session with new tokens
                    expires_at = datetime.now() + timedelta(seconds=expires_in)
                    request.session['scalekit_tokens'] = {
                        'access_token': new_access_token,
                        'refresh_token': token_response.get('refresh_token', refresh_token),
                        'id_token': token_response.get('id_token', token_data.get('id_token')),
                        'expires_at': expires_at.isoformat(),
                        'expires_in': expires_in,
                    }
                    
                    # Now try to get claims with the new token
                    claims = client.get_user_info(new_access_token)
                except Exception as refresh_error:
                    logger.error(f"Failed to refresh token: {refresh_error}")
                    claims = {}
            else:
                logger.warning(f"Could not retrieve claims from access token: {e}")
                claims = {}
    else:
        claims = {}
    
    # Re-read token_data in case it was updated during refresh
    token_data = request.session.get('scalekit_tokens', {})
    
    # Parse expires_at (after potential token refresh)
    expires_at = None
    if token_data.get('expires_at'):
        try:
            expires_at = datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
        except:
            pass
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user_data,
        "name": user_data.get('name', 'User'),
        "email": user_data.get('email', ''),
        "subject": user_data.get('sub', ''),
        "claims": claims,
        "roles": roles,
        "permissions": permissions,
        "token_expires_at": expires_at,
        "has_access_token": bool(token_data.get('access_token')),
        "has_refresh_token": bool(token_data.get('refresh_token')),
        "access_token": token_data.get('access_token', ''),
        "refresh_token": token_data.get('refresh_token', ''),
    })


@router.post("/logout", name="logout_view")
async def logout_view(request: Request):
    """
    Logout the user from both FastAPI and Scalekit.
    Route: /logout
    """
    token_data = request.session.get('scalekit_tokens', {})
    access_token = token_data.get('access_token')
    
    # Get logout URL from Scalekit SDK
    if access_token:
        try:
            client = scalekit_client()
            logout_url = client.logout(access_token)
            # Clear all session data
            request.session.clear()
            # Redirect to Scalekit logout URL instead of just clearing session
            # This ensures proper logout on Scalekit side
            return RedirectResponse(url=logout_url, status_code=status.HTTP_302_FOUND)
        except Exception as e:
            logger.error(f"Error during Scalekit logout: {e}")
    
    # Clear all session data
    request.session.clear()
    
    logger.info("User logged out")
    
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.get("/sessions", response_class=HTMLResponse, name="sessions_view")
async def sessions_view(request: Request, user: dict = Depends(require_login)):
    """
    Display current session information.
    Route: /sessions
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    
    # Calculate token expiry info
    expires_at = None
    minutes_until_expiry = None
    is_expired = False
    is_expiring_soon = False
    
    if token_data.get('expires_at'):
        try:
            expires_at = datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
            now = datetime.now()
            if expires_at.tzinfo:
                now = datetime.now(expires_at.tzinfo)
            
            delta = expires_at - now
            minutes_until_expiry = int(delta.total_seconds() / 60)
            is_expired = delta.total_seconds() < 0
            is_expiring_soon = 0 <= minutes_until_expiry <= 5
        except Exception as e:
            logger.error(f"Error parsing expires_at: {e}")
    
    return templates.TemplateResponse("sessions.html", {
        "request": request,
        "user": user_data,
        "session_info": {
            "userId": user_data.get('sub'),
            "email": user_data.get('email'),
            "name": user_data.get('name'),
            "hasAccessToken": bool(token_data.get('access_token')),
            "hasRefreshToken": bool(token_data.get('refresh_token')),
        },
        "expiry_info": {
            "expiresAt": expires_at,
            "minutesUntilExpiry": minutes_until_expiry,
            "isExpired": is_expired,
            "isExpiringSoon": is_expiring_soon,
        },
        "is_token_expired": is_expired,
        "is_token_expiring_soon": is_expiring_soon,
        # Token values for display
        "access_token": token_data.get('access_token', ''),
        "refresh_token": token_data.get('refresh_token', ''),
        "id_token": token_data.get('id_token', ''),
    })


@router.post("/sessions/validate-token", name="validate_token_view")
async def validate_token_view(request: Request, user: dict = Depends(require_login)):
    """
    Validate the current access token (API endpoint).
    Route: /sessions/validate-token (POST)
    """
    token_data = request.session.get('scalekit_tokens', {})
    access_token = token_data.get('access_token')
    
    if not access_token:
        return JSONResponse({
            "valid": False,
            "error": "No access token found"
        })
    
    try:
        client = scalekit_client()
        user_info = client.get_user_info(access_token)
        
        return JSONResponse({
            "valid": True,
            "claims": user_info,
            "message": "Token is valid",
            "userId": user_info.get('sub'),
            "email": user_info.get('email'),
            "name": user_info.get('name'),
        })
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return JSONResponse({
            "valid": False,
            "error": f"Token validation failed: {str(e)}"
        })


@router.post("/sessions/refresh-token", name="refresh_token_view")
async def refresh_token_view(request: Request, user: dict = Depends(require_login)):
    """
    Refresh the access token (API endpoint).
    Route: /sessions/refresh-token (POST)
    """
    token_data = request.session.get('scalekit_tokens', {})
    refresh_token = token_data.get('refresh_token')
    
    if not refresh_token:
        return JSONResponse({
            "success": False,
            "error": "No refresh token available. Make sure you requested the 'offline_access' scope during authentication."
        })
    
    try:
        client = scalekit_client()
        token_response = client.refresh_access_token(refresh_token)
        
        # Always try to decode JWT first to get actual expiry from the token itself
        # The JWT exp claim is the source of truth for when the token actually expires
        access_token = token_response.get('access_token')
        expires_in = None
        
        if access_token:
            try:
                import base64
                import json
                # Decode JWT without verification to get exp claim
                # Split the token and decode the payload (second part)
                parts = access_token.split('.')
                if len(parts) >= 2:
                    # Decode the payload (second part)
                    payload = parts[1]
                    # Add padding if needed for base64 decoding
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += '=' * padding
                    decoded = base64.urlsafe_b64decode(payload)
                    claims = json.loads(decoded)
                    exp = claims.get('exp')
                    if exp:
                        # exp is Unix timestamp, calculate expires_in
                        from datetime import timezone
                        now_ts = datetime.now(timezone.utc).timestamp()
                        expires_in = int(exp - now_ts)
            except Exception:
                pass
        
        # Fallback to response expires_in if JWT decoding failed
        if not expires_in:
            expires_in = (
                token_response.get('expires_in') or 
                token_response.get('expiresIn') or
                3600
            )
        
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        request.session['scalekit_tokens'] = {
            'access_token': token_response.get('access_token'),
            'refresh_token': token_response.get('refresh_token', refresh_token),  # Keep old if not provided
            'id_token': token_response.get('id_token', token_data.get('id_token')),
            'expires_at': expires_at.isoformat(),
            'expires_in': expires_in,
        }
        
        return JSONResponse({
            "success": True,
            "message": "Tokens refreshed successfully",
            "newAccessToken": token_response.get('access_token'),
            "newRefreshToken": token_response.get('refresh_token'),
            "newIdToken": token_response.get('id_token'),
        })
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return JSONResponse({
            "success": False,
            "error": f"Token refresh failed: {str(e)}"
        })


@router.get("/organization/settings", response_class=HTMLResponse, name="organization_settings_view")
async def organization_settings_view(request: Request, user: dict = Depends(require_permission('organization:settings'))):
    """
    Protected organization settings page.
    Requires 'organization:settings' permission in the access token.
    Route: /organization/settings
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    
    # Get access token to validate and show permissions
    access_token = token_data.get('access_token')
    client = scalekit_client()
    
    # Get token claims to show permissions
    claims = {}
    permissions = []
    if access_token:
        try:
            claims = client.validate_token_and_get_claims(access_token)
            permissions = (
                claims.get('permissions', []) or
                claims.get('https://scalekit.com/permissions', []) or
                claims.get('scalekit:permissions', []) or
                []
            )
        except Exception as e:
            logger.error(f"Error getting token claims: {e}")
    
    return templates.TemplateResponse("organization_settings.html", {
        "request": request,
        "user": user_data,
        "name": user_data.get('name', 'User'),
        "email": user_data.get('email', ''),
        "permissions": permissions,
        "has_organization_settings": 'organization:settings' in permissions,
    })

