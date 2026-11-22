import json
import os
from datetime import datetime, timezone

from sqlalchemy import (Column, DateTime, Integer, MetaData, String, Table, Text,
                        create_engine, insert, select)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///history.db")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

scans = Table(
    "scans", metadata,
    Column("id", Integer, primary_key=True),
    Column("scanned_at", DateTime(timezone=True), nullable=False),
    Column("source", String(255)),
    Column("sender", String(500)),
    Column("subject", String(500)),
    Column("score", Integer, nullable=False),
    Column("verdict", String(20), nullable=False),
    Column("findings", Text, nullable=False),
)


def init_db():
    metadata.create_all(engine)


def save_scan(source, result):
    with engine.begin() as conn:
        conn.execute(insert(scans).values(
            scanned_at=datetime.now(timezone.utc),
            source=source,
            sender=result["from"],
            subject=result["subject"],
            score=result["score"],
            verdict=result["verdict"],
            findings=json.dumps(result["findings"]),
        ))


def list_scans(limit=20):
    with engine.connect() as conn:
        rows = conn.execute(
            select(scans).order_by(scans.c.id.desc()).limit(limit)
        ).mappings().all()
    return [dict(row) for row in rows]
