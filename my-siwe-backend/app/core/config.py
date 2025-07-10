# Configuration management using pydantic-settings
from pydantic_settings import BaseSettings
import secrets

class Settings(BaseSettings):
    # Generate a secure secret key if not provided
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours

    class Config:
        env_file = ".env"

settings = Settings()