from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
try:
    from .config import DATABASE_URL        # when imported as sidecar.db
except ImportError:
    from config import DATABASE_URL 

# Create the SQLAlchemy engine. For SQLite, echo=False to avoid noisy logs.
engine = create_engine(
    DATABASE_URL,
    pool_size=25,          # start with ~VUs
    max_overflow=50,       # burst
    pool_timeout=10,       # fail fast instead of hanging 30s
    pool_pre_ping=True,
    pool_recycle=1800,
    future=True,
)


# Classic session factory
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

# Base class for our ORM models
Base = declarative_base()

def get_db():
    """
    FastAPI dependency that yields a SQLAlchemy session and
    ensures it is closed after the request.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()