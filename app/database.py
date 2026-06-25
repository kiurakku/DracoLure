import os

import psycopg2


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "db"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        database=os.environ.get("POSTGRES_DB", "honeypot"),
        user=os.environ.get("POSTGRES_USER", "honeypot"),
        password=os.environ.get("POSTGRES_PASSWORD", "honeypot_secret"),
    )
