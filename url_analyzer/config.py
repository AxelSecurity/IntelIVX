from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Azure AI Foundry Agent
    foundry_endpoint: str
    foundry_agent_name: str       # nome agente nel portale Foundry  (es. "agent-intelivx")
    foundry_agent_version: str    # versione agente pubblicata        (es. "4")

    # Azure AD — Service Principal per autenticazione Foundry
    # Se non impostati, usa DefaultAzureCredential (az login / Managed Identity)
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # Playwright
    playwright_timeout_ms: int = 30000
    playwright_screenshot: bool = False
    playwright_ocr: bool = True     # OCR su viewport per rilevare testo in immagini/loghi

    # Worker
    n_workers: int = 3
    job_ttl_seconds: int = 3600

    # Trellix IVX — Token Auth (opzionale)
    trellix_api_token: str = ""


settings = Settings()
