from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    anthropic_api_key: str
    anthropic_model_scope: str = "claude-haiku-4-5"
    anthropic_model_plan: str = "claude-sonnet-4-6"
    anthropic_model_filter: str = "claude-sonnet-4-6"
    anthropic_model_poc: str = "claude-sonnet-4-6"
    anthropic_model_report: str = "claude-opus-4-7"
    anthropic_model_rewrite: str = "claude-sonnet-4-6"
    # Comma-separated model list tried after the task-specific primary model.
    anthropic_model_fallbacks: str = "claude-sonnet-4-6,claude-haiku-4-5"

    # Estimated per-1M token pricing used for UI scan-cost telemetry.
    anthropic_cost_opus_input_per_mtok: float = 15.0
    anthropic_cost_opus_output_per_mtok: float = 75.0
    anthropic_cost_sonnet_input_per_mtok: float = 3.0
    anthropic_cost_sonnet_output_per_mtok: float = 15.0
    anthropic_cost_haiku_input_per_mtok: float = 0.8
    anthropic_cost_haiku_output_per_mtok: float = 4.0

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
    h1_username: Optional[str] = None    # HackerOne API token for program discovery.
    # Generate at: https://hackerone.com/settings/api_token/edit
    h1_api_token: Optional[str] = None
    # Optional remote curated CVE CSV URL for version-based matching database.
    # If set, backend refreshes the local CSV on startup and then periodically.
    cve_csv_remote_url: Optional[str] = None
    cve_csv_refresh_hours: int = 24
    # How many recent years from cvelistV5 to process into matcher CSV.
    cve_cvelist_years_back: int = 8
    # Hard cap to keep generated CSV bounded and scan-time matching fast.
    cve_cvelist_max_rows: int = 20000

    # WPScan API token (https://wpscan.com/register — free tier: 25 req/day)
    wpscan_api_token: Optional[str] = None

    # Telegram notifications (optional)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
