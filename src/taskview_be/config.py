from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    taskview_ai_url: str = "http://127.0.0.1:8100"
    taskview_ai_shared_secret: SecretStr | None = None
    taskview_database_url: str = "postgresql://taskview:taskview@127.0.0.1:54329/taskview"
    taskview_be_fake_ai: bool = False
    taskview_session_days: int = 7
    taskview_login_max_failures: int = 5
    taskview_login_lock_minutes: int = 15
    taskview_email_token_minutes: int = 30
    taskview_require_email_verification: bool = False
    taskview_password_reset_minutes: int = 30
    taskview_expose_dev_tokens: bool = False
    taskview_delivery_encryption_key: SecretStr | None = None
    taskview_public_web_url: str = "http://localhost:3000"
    taskview_cors_origins: str = "http://localhost:3000"
    taskview_smtp_host: str | None = None
    taskview_smtp_port: int = 1025
    taskview_smtp_username: str | None = None
    taskview_smtp_password: SecretStr | None = None
    taskview_smtp_from_email: str = "Needex <no-reply@taskview.local>"
    taskview_smtp_use_tls: bool = False
    taskview_smtp_use_starttls: bool = False
    taskview_smtp_timeout_seconds: float = 10.0
    taskview_mail_worker_enabled: bool = True
    taskview_mail_worker_poll_seconds: float = 2.0
    taskview_mail_worker_batch_size: int = 20
    taskview_mail_worker_max_attempts: int = 6
    taskview_mail_worker_claim_seconds: int = 60
    taskview_google_client_id: str | None = None
    taskview_google_client_secret: str | None = None
    taskview_google_redirect_uri: str = "http://localhost:3000/api/auth/google/callback"
    # Data-source access is fail-closed unless both a hostname and every
    # resolved network range are explicitly allowed.
    taskview_data_source_allowed_hostnames: str = ""
    taskview_data_source_allowed_cidrs: str = ""
    taskview_data_source_require_tls: bool = True
    taskview_data_source_verify_tls: bool = True
    taskview_data_source_tls_ca_file: str | None = None
    taskview_data_source_connect_timeout_seconds: float = 3.0
    taskview_data_source_command_timeout_seconds: float = 3.0
    taskview_data_source_close_timeout_seconds: float = 1.0
    taskview_data_source_max_catalog_fields: int = 5000
    taskview_data_source_scan_job_ttl_seconds: int = 900
    taskview_data_source_encryption_key: SecretStr | None = None
    taskview_public_demo_timeout_seconds: float = 30.0
    taskview_public_demo_user_agent: str = "Needex/1.0 public-data-demo"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
