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

    # Optional remote curated CVE CSV URL for version-based matching database.
    # If set, backend refreshes the local CSV on startup and then periodically.
    cve_csv_remote_url: Optional[str] = None
    cve_csv_refresh_hours: int = 24
    # How many recent years from cvelistV5 to process into matcher CSV.
    cve_cvelist_years_back: int = 8
    # Hard cap to keep generated CSV bounded and scan-time matching fast.
    cve_cvelist_max_rows: int = 20000

    # Telegram notifications (optional)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
