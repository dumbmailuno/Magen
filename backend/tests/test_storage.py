from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import inspect, select

from app.models.db import FindingRecord, ProbeAudit, Scan, Target
from app.storage.database import Database


def test_migration_creates_tables_and_no_secret_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "magen.db")
    db.migrate()
    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    assert {"targets", "scans", "findings", "probe_audit"} <= tables
    for table in tables:
        for col in insp.get_columns(table):
            assert not any(
                word in col["name"].lower()
                for word in ("auth_header", "token", "cookie", "password")
            ), f"{table}.{col['name']} looks like a secret column"
    db.dispose()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "magen.db")
    db.migrate()
    db.migrate()
    db.dispose()


def test_round_trip(tmp_path: Path) -> None:
    db = Database(tmp_path / "magen.db")
    db.migrate()
    now = datetime.now(tz=UTC)
    with db.session() as s:
        t = Target(host="localhost", is_local=True, authorized_at=now, created_at=now)
        scan = Scan(
            target=t, status="done", started_at=now, magen_version="0.1.0", commit="abc", options={}
        )
        scan.findings.append(
            FindingRecord(
                finding_id="a" * 20,
                rule_id="API-OAS-001",
                severity="high",
                status="potential",
                position=0,
                payload="{}",
                reviewed=False,
            )
        )
        s.add(scan)
        s.flush()
        s.add(
            ProbeAudit(
                scan_id=scan.id, sent_at=now, method="GET", url="http://localhost/", status_code=200
            )
        )
    with db.session() as s:
        rec = s.scalars(select(FindingRecord)).one()
        assert rec.scan.target is not None and rec.scan.target.host == "localhost"
    db.dispose()
