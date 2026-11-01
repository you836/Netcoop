from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import settings


def _build_engine():
    db_url = (settings.database_url or "sqlite:///./netcoop.db").strip()

    # Render sometimes provides postgres:// instead of postgresql://
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[len("postgres://") :]

    # If DATABASE_URL points to localhost on a cloud server where local Postgres isn't running,
    # or if a specific driver is missing, try creating the engine and fall back cleanly to SQLite.
    try:
        eng = create_engine(db_url, pool_pre_ping=True)
        # Test dialect driver import & reachability if localhost is used
        if "@localhost" in db_url or "@127.0.0.1" in db_url:
            with eng.connect() as _:
                pass
        return eng
    except Exception as exc:
        print(f"[DATABASE] Falling back to local SQLite './netcoop.db' (reason: {exc})")
        return create_engine(
            "sqlite:///./netcoop.db",
            connect_args={"check_same_thread": False},
        )


engine = _build_engine()

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
