"""
Configuration settings loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "API VAPT Tool"
    APP_ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./vapt_tool.db"
    
    # CORS — frontend dev server
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    
    # Scan defaults
    DEFAULT_RATE_LIMIT_RPS: float = 2.0     # requests per second
    DEFAULT_CONCURRENCY: int = 5             # concurrent workers
    DEFAULT_TIMEOUT: float = 30.0            # seconds per request
    DEFAULT_RETRIES: int = 2
    MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # Safe mode — destructive modules disabled by default
    DEFAULT_SAFE_MODE: bool = True
    
    # Reports output directory
    REPORTS_DIR: str = "./reports_output"
    
    # Audit log retention (days)
    AUDIT_LOG_RETENTION_DAYS: int = 365
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
