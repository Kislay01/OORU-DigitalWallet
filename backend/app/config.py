from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET = "dev-only-secret-key-change-me-0123456789"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite+aiosqlite:///./wallet.db"

    secret_key: str = _DEV_SECRET
    token_ttl_seconds: int = 3600
    token_issuer: str = "ooru-campus-id"
    token_audience: str = "ooru-portals"

    public_base_url: str = "http://localhost:8000"
    key_dir: str = "./keys"
    portals_dir: str | None = None

    cors_origins: list[str] = [
        "http://localhost:3002",
        "http://127.0.0.1:3002",
        "http://localhost:5173",
    ]

    seed_admin_username: str = "admin"
    seed_admin_password: str = "admin123"
    seed_verifier_username: str = "verifier"
    seed_verifier_password: str = "verifier123"

    @model_validator(mode="after")
    def _production_guard(self) -> "Settings":
        if self.environment.lower() == "production":
            weak = {_DEV_SECRET, "admin123", "verifier123", "change_me"}
            if self.secret_key in weak or len(self.secret_key) < 32:
                raise ValueError("SECRET_KEY must be a random value of at least 32 characters in production")
            if {self.seed_admin_password, self.seed_verifier_password} & weak:
                raise ValueError("Default seed passwords cannot be used in production")
        return self


settings = Settings()
