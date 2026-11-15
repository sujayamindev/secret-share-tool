"""
SQLite engine + session factory. Deliberately simple — this is a single-table-pair
app, an ORM session-per-request pattern is plenty, no need for connection pooling
complexity that would matter at higher concurrency.
"""
import os

from sqlalchemy import create_engine, delete, event, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_settings

settings = get_settings()

# Ensure the data directory exists (so the volume-mounted SQLite file has somewhere to live)
db_path = settings.DATABASE_URL.replace("sqlite:///", "")
os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

# check_same_thread=False is required for SQLite + FastAPI's threaded request handling.
# Safe here because SQLAlchemy's sessionmaker gives each request its own Session object.
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, _connection_record):
    # By default SQLite only marks a deleted row's pages as free; the bytes
    # stay in the file until something overwrites them. secure_delete makes
    # SQLite zero them at delete time. This is best-effort (a rollback journal
    # or a filesystem snapshot can still hold old pages), and it is not what
    # the confidentiality of a secret rests on — that is the key the server
    # never had. It just means "deleted" is as true as SQLite can make it.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA secure_delete = ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session per request, closes it after."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class SchemaMismatchError(RuntimeError):
    pass


def verify_schema() -> None:
    """There is no migration framework (deliberately, at this size), and
    `create_all` never alters a table that already exists. So a database file
    from an older version of the app would otherwise fail on the first query
    with an obscure 'no such column' error. Check up front and say what to do."""
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        expected = {column.name for column in table.columns}
        if existing != expected:
            raise SchemaMismatchError(
                f"Table '{table.name}' in {settings.DATABASE_URL} was created by a "
                "different version of this app. There are no migrations: stop the "
                "app, delete the database file, and start it again."
            )


def purge_expired() -> tuple[int, int]:
    """Delete expired secrets and sessions. Returns (secrets, sessions) removed.

    Expiry is also checked on every read, so this is not what makes an expired
    row unusable. It is what makes the row actually go away, so that 'expires
    after 24 hours' describes the disk and not just the application logic."""
    # Imported here: models imports Base from this module.
    from app.models import Secret, UserSession, _utcnow

    now = _utcnow()
    with SessionLocal() as db:
        secrets_removed = db.execute(delete(Secret).where(Secret.expires_at <= now)).rowcount
        sessions_removed = db.execute(
            delete(UserSession).where(UserSession.expires_at <= now)
        ).rowcount
        db.commit()
    return secrets_removed, sessions_removed
