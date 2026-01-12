"""
Configuration settings for the FastAPI Scalekit application.
"""
import os
from typing import List
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Scalekit Configuration
    scalekit_env_url: str = os.getenv('SCALEKIT_ENV_URL', os.getenv('SCALEKIT_DOMAIN', ''))
    scalekit_client_id: str = os.getenv('SCALEKIT_CLIENT_ID', '')
    scalekit_client_secret: str = os.getenv('SCALEKIT_CLIENT_SECRET', '')
    scalekit_redirect_uri: str = os.getenv('SCALEKIT_REDIRECT_URI', 'http://localhost:8000/auth/callback')
    scalekit_scopes: List[str] = os.getenv('SCALEKIT_SCOPES', 'openid profile email offline_access').split()
    
    # Server Configuration
    debug: bool = os.getenv('DEBUG', 'True') == 'True'
    secret_key: str = os.getenv('SECRET_KEY', 'fastapi-secret-key-change-me-in-production')
    
    # Session Configuration
    session_cookie_name: str = 'session'
    session_max_age: int = 3600  # 1 hour
    
    class Config:
        case_sensitive = False


settings = Settings()

