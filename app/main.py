"""
FastAPI main application file.
"""
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.config import settings
from app.middleware import ScalekitTokenRefreshMiddleware
from app.routes import router

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="FastAPI Scalekit Authentication Example",
    description="A FastAPI application demonstrating OIDC authentication with Scalekit",
    version="1.0.0",
    debug=settings.debug,
)

# Add custom token refresh middleware (innermost - processes last)
# Note: This middleware needs session to be available, so SessionMiddleware must be added after this
app.add_middleware(ScalekitTokenRefreshMiddleware)

# Add session middleware (must be added after ScalekitTokenRefreshMiddleware)
# In Starlette, middleware added later wraps earlier middleware and processes first
# So SessionMiddleware will process before ScalekitTokenRefreshMiddleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=settings.session_max_age,
    same_site='lax',
    https_only=False,  # Set to True in production with HTTPS
)

# Add GZip compression (outermost - processes first)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include routers
app.include_router(router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


# Make templates available globally (for error handling)
from fastapi.templating import Jinja2Templates
from pathlib import Path

# Get the project root directory (parent of app directory)
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.exception_handler(403)
async def permission_denied_handler(request: Request, exc):
    """Handle 403 Forbidden errors with a custom template."""
    return templates.TemplateResponse(
        "permission_denied.html",
        {
            "request": request,
            "user": request.session.get('scalekit_user', {}),
        },
        status_code=403
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )

