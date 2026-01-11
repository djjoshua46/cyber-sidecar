"""
Simple script to initialize the database tables.

Run this inside the container or locally while the DB is up:
    python -m sidecar.init_db
"""

from .db import Base, engine
from .models import Event, Export


def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
