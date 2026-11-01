import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure the backend directory is in sys.path so 'app' can always be imported
backend_dir = Path(__file__).resolve().parent.parent
project_root = backend_dir.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
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


# Serve built frontend (dist/) if available so a single Render Web Service can host both
dist_dir = backend_dir / "dist" if (backend_dir / "dist" / "index.html").exists() else project_root / "dist"
if dist_dir.exists() and (dist_dir / "index.html").exists():
    print(f"[FRONTEND] Serving static dashboard from: {dist_dir}")
    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/")
    def serve_root():
        return FileResponse(str(dist_dir / "index.html"))

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        candidate = dist_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(dist_dir / "index.html"))
else:
    print(f"[FRONTEND WARNING] No dist/index.html found in {backend_dir / 'dist'} or {project_root / 'dist'}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
