from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.models import Base

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "nmaper" / "nmaper.db"


def resolve_database_url(db_path: Path | None = None) -> str:
    path = (db_path or DEFAULT_DB_PATH).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path}"


def create_db_engine(db_path: Path | None = None, echo: bool = False) -> Engine:
    return create_engine(
        resolve_database_url(db_path),
        echo=echo,
        future=True,
    )


def create_session_factory(
    db_path: Path | None = None, echo: bool = False
) -> sessionmaker[Session]:
    engine = create_db_engine(db_path=db_path, echo=echo)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db(db_path: Path | None = None, echo: bool = False) -> Engine:
    engine = create_db_engine(db_path=db_path, echo=echo)
    Base.metadata.create_all(engine)
    return engine


@contextmanager
def session_scope(db_path: Path | None = None, echo: bool = False) -> Iterator[Session]:
    session_factory = create_session_factory(db_path=db_path, echo=echo)
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
