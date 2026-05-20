from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    anthropic_api_key: str
    redis_url: str = "redis://localhost:6379"
    workspace_dir: str = "/app/workspace"
    log_level: str = "INFO"

    # Optional free-tier API keys
    virustotal_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    ipinfo_token: Optional[str] = None

    # GitHub token for dorking (https://github.com/settings/tokens — read:public_repo)
    github_token: Optional[str] = None

    # HackerOne researcher username — added as X-HackerOne-Researcher header to
    # all active-recon requests, as required by many H1 programs (e.g. Coupang).
    h1_username: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()
