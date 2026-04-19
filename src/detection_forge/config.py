# src/detection_forge/config.py
from enum import Enum
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProviderName(str, Enum):
    GEMINI = "gemini"
    GROQ = "groq"
    OLLAMA = "ollama"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str = "sqlite+aiosqlite:///./data/detection_forge.db"
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    llm_primary: LLMProviderName = LLMProviderName.GEMINI
    llm_fallback: list[LLMProviderName] = [LLMProviderName.GROQ, LLMProviderName.OLLAMA]
    llm_max_retries: int = 2

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"

    embed_model: str = "all-MiniLM-L6-v2"

    debug: bool = False


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
