# backend_fastapi/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./chat_history.db"

# create_engine is the entry point to the database.
# The 'check_same_thread' argument is needed only for SQLite.
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Each SessionLocal instance will be a database session.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base will be used to create our ORM models (the database tables).
Base = declarative_base()