"""
Custom middleware for Scalekit token refresh and session management.
"""
import logging
from datetime import timedelta, datetime
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from app.scalekit_client import scalekit_client

logger = logging.getLogger(__name__)


class ScalekitTokenRefreshMiddleware(BaseHTTPMiddleware):
    """
    Middleware that automatically refreshes expired Scalekit access tokens.
    Uses session-based storage.
    
    This middleware:
    1. Checks if the user has an active Scalekit session
    2. Validates if the access token is expired or about to expire
    3. Automatically refreshes the token if needed
    4. Updates the session with new token information
    """
    
    async def dispatch(self, request: Request, call_next):
        # Check if session is available (SessionMiddleware must be installed)
        if "session" not in request.scope:
            return await call_next(request)
        
        # Skip token refresh for unauthenticated users
        if not request.session.get('scalekit_user'):
            return await call_next(request)
        
        # Skip token refresh for certain paths
        skip_paths = ['/login', '/auth/callback', '/logout', '/static/', '/sessions/refresh-token']
        if any(request.url.path.startswith(path) for path in skip_paths):
            return await call_next(request)
        
        try:
            # Get token data from session
            token_data = request.session.get('scalekit_tokens', {})
            if not token_data:
                return await call_next(request)
            
            # Check if token is expired or about to expire
            expires_at_str = token_data.get('expires_at')
            if not expires_at_str:
                return await call_next(request)
            
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if expires_at.tzinfo is None:
                    # Make timezone-aware if not already
                    from datetime import timezone as tz
                    expires_at = expires_at.replace(tzinfo=tz.utc)
            except Exception as e:
                logger.error(f"Error parsing expires_at: {e}")
                return await call_next(request)
            
            # Check if token is expired or expiring soon (within 1 minute)
            buffer_time = timedelta(minutes=1)
            now = datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now()
            if now + buffer_time >= expires_at:
                # Token is expired or expiring soon, try to refresh it
                refresh_token = token_data.get('refresh_token')
                if refresh_token:
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
                                parts = access_token.split('.')
                                if len(parts) >= 2:
                                    payload = parts[1]
                                    # Add padding if needed
                                    padding = 4 - len(payload) % 4
                                    if padding != 4:
                                        payload += '=' * padding
                                    decoded = base64.urlsafe_b64decode(payload)
                                    claims = json.loads(decoded)
                                    exp = claims.get('exp')
                                    if exp:
                                        # exp is Unix timestamp, calculate expires_in
                                        from datetime import timezone
                                        if now.tzinfo:
                                            now_ts = now.timestamp()
                                        else:
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
                        
                        new_expires_at = now + timedelta(seconds=expires_in)
                        
                        request.session['scalekit_tokens'] = {
                            'access_token': token_response.get('access_token'),
                            'refresh_token': token_response.get('refresh_token', refresh_token),
                            'id_token': token_response.get('id_token', token_data.get('id_token')),
                            'expires_at': new_expires_at.isoformat(),
                            'expires_in': expires_in,
                        }
                    except Exception as e:
                        logger.error(f"Failed to refresh token: {e}")
                        # If refresh fails, user will need to re-authenticate
                else:
                    logger.warning("No refresh token available")
        
        except Exception as e:
            logger.error(f"Error in token refresh middleware: {e}")
        
        return await call_next(request)

