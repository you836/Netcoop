import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure the backend directory is in sys.path so 'app' can always be imported
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import Base, engine
from app.models import entities  # noqa: F401 - register SQLAlchemy tables
from app.api.routes.diagnostics import router as diag_router


def init_db_tables() -> None:
    """Creates all relational tables (incidents, telemetry, agent_messages, diagnostic_reports)."""
    try:
        Base.metadata.create_all(bind=engine)
        print("[DATABASE] All tables verified/created successfully.")
    except Exception as exc:
        print(f"[DATABASE WARNING] Could not auto-create tables on startup: {exc}")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db_tables()
    yield


# Ensure tables exist immediately when module is loaded
init_db_tables()

app = FastAPI(
    title="NetCoop AI Diagnostic Service",
    description="Multi-agent network fault diagnosis service for real and synthetic telemetry",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(diag_router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "netcoop-backend"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
