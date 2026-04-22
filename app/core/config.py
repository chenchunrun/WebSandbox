from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "malicious-site-sandbox"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    database_url: str = "postgresql+psycopg://postgres:postgres@postgres:5432/sandboxdb"
    redis_url: str = "redis://redis:6379/0"

    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_secure: bool = False
    minio_bucket: str = "sandbox-artifacts"

    openai_base_url: str | None = None
    openai_api_key: str | None = None
    openai_model_text: str = "gpt-4o-mini"
    openai_model_vision: str = "gpt-4o-mini"

    xgboost_model_path: str = "/app/models/xgb_model.joblib"
    model_artifact_dir: str = "/app/models"

    crawl_timeout_seconds: int = 30
    crawl_timeout_quick_seconds: int = 20
    crawl_timeout_standard_seconds: int = 30
    crawl_timeout_deep_seconds: int = 45
    max_dom_chars: int = 600000
    max_network_events: int = 300
    max_redirect_chain: int = 20
    max_batch_size: int = 1000
    allow_private_target_urls: bool = False
    allow_private_callback_urls: bool = False
    callback_allowlist: str | None = None
    isolation_mode: str = Field(default="local", pattern="^(local|docker_task)$")
    sandbox_image: str = "websandbox-worker:latest"
    sandbox_network: str = "websandbox_default"
    sandbox_cpu_limit: float = 1.0
    sandbox_memory_limit: str = "1g"
    sandbox_pids_limit: int = 256
    sandbox_timeout_retries: int = 1
    sandbox_retry_timeout_multiplier: float = 1.5
    sandbox_fallback_to_local_on_timeout: bool = True
    sandbox_fallback_timeout_seconds: int = 45
    celery_task_time_limit_seconds: int = 300
    queue_quick: str = "quick"
    queue_standard: str = "standard"
    queue_deep: str = "deep"
    queue_retry: str = "retry"
    worker_queues: str = "quick,standard,deep,retry"
    governance_api_key: str | None = None
    rule_malicious_threshold: float = 0.82
    rule_benign_threshold: float = 0.25
    action_block_confidence: float = 0.8
    action_benign_observe_confidence: float = 0.7
    deep_escalation_enabled: bool = True
    deep_escalation_keyword_hit_threshold: int = 2
    deep_escalation_high_risk_xhr_threshold: int = 1
    policy_cache_ttl_seconds: int = 2


@lru_cache
def get_settings() -> Settings:
    return Settings()
