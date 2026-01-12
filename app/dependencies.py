"""
FastAPI dependencies for authentication and authorization.
"""
from typing import Union
from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
from starlette.responses import Response
from app.scalekit_client import scalekit_client


def get_scalekit_user(request: Request):
    """
    Dependency to get the current authenticated user from session.
    Raises HTTPException if user is not authenticated.
    """
    user = request.session.get('scalekit_user')
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user


def get_scalekit_tokens(request: Request):
    """
    Dependency to get the current tokens from session.
    Raises HTTPException if tokens are not found.
    """
    tokens = request.session.get('scalekit_tokens', {})
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No tokens found. Please log in again."
        )
    return tokens


def require_login(request: Request) -> Union[dict, RedirectResponse]:
    """
    Dependency that checks if user is authenticated.
    Redirects to login if not authenticated.
    """
    user = request.session.get('scalekit_user')
    if not user:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=status.HTTP_302_FOUND)
    return user


def require_permission(permission: str):
    """
    Dependency factory that checks if user has a specific permission.
    
    Args:
        permission: Permission name required (e.g., 'organization:settings')
    
    Returns:
        Dependency function that can be used in FastAPI routes
    """
    def permission_checker(request: Request) -> Union[dict, RedirectResponse]:
        # First check if user is authenticated
        user = request.session.get('scalekit_user')
        if not user:
            return RedirectResponse(url=f"/login?next={request.url.path}", status_code=status.HTTP_302_FOUND)
        
        # Get access token from session
        token_data = request.session.get('scalekit_tokens', {})
        access_token = token_data.get('access_token')
        
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No access token found. Please log in again."
            )
        
        # Check permission using Scalekit SDK
        client = scalekit_client()
        if not client.has_permission(access_token, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        
        return user
    
    return permission_checker

