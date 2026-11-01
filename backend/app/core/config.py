import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env file explicitly if present
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class Settings(BaseSettings):
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./netcoop.db")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    # Tried in order if the primary model is unavailable (retired / no access).
    groq_fallback_models: str = os.getenv(
        "GROQ_FALLBACK_MODELS",
        "qwen/qwen3.8-27b,openai/gpt-oss-20b,llama-3.3-70b-versatile",
    )

settings = Settings()
