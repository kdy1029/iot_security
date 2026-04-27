import os
import psycopg2
from sqlalchemy import create_engine

def get_db_uri() -> str:
    """
    Returns the PostgreSQL connection URI from the PG_DSN environment variable.
    Example: postgresql://user:password@localhost:5432/dbname
    """
    uri = os.environ.get("PG_DSN")
    if not uri:
        raise ValueError(
            "Environment variable PG_DSN is not set. "
            "Please configure it (e.g. export PG_DSN='postgresql://postgres:password@localhost:5432/iot_security')"
        )
    return uri

def get_connection():
    """Returns a psycopg2 database connection."""
    return psycopg2.connect(get_db_uri())

def get_engine():
    """Returns a SQLAlchemy engine."""
    return create_engine(get_db_uri())
