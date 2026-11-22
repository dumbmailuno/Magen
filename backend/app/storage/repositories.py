"""Persistence for targets, scans, findings and the probe audit log.

Nothing here ever receives the user's auth header value: callers pass only redacted data.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select, update

from app.core.errors import NotFoundError, ValidationFailedError
from app.models.db import FindingRecord, ProbeAudit, Scan, Target
from app.models.finding import Finding
from app.runtime.client import AuditEntry
from app.storage.database import Database


def _now() -> datetime:
    return datetime.now(tz=UTC)


class TargetRepository:
    """The allowlist."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def list(self) -> list[Target]:
        """All targets, by host."""
        with self.db.session() as s:
            return list(s.scalars(select(Target).order_by(Target.host)))

    def get(self, target_id: int) -> Target:
        """One target or 404."""
        with self.db.session() as s:
            target = s.get(Target, target_id)
            if target is None:
                raise NotFoundError("Target not found")
            return target

    def add(self, host: str, *, is_local: bool) -> Target:
        """Add a host with the authorization timestamp recorded now."""
        with self.db.session() as s:
            if s.scalar(select(Target).where(Target.host == host)) is not None:
                raise ValidationFailedError(f"{host} is already on the allowlist")
            now = _now()
            target = Target(host=host, is_local=is_local, authorized_at=now, created_at=now)
            s.add(target)
            s.flush()
            return target

    def delete(self, target_id: int) -> None:
        """Remove from the allowlist; past scans are kept (detached from the target)."""
        with self.db.session() as s:
            target = s.get(Target, target_id)
            if target is None:
                raise NotFoundError("Target not found")
            s.execute(update(Scan).where(Scan.target_id == target_id).values(target_id=None))
            s.delete(target)


class ScanRepository:
    """Scans, their findings and the audit trail."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self, *, target_id: int | None, options: dict[str, object], version: str, commit: str
    ) -> int:
        """Insert a running scan and return its id."""
        with self.db.session() as s:
            scan = Scan(
                target_id=target_id,
                status="running",
                started_at=_now(),
                magen_version=version,
                commit=commit,
                options=options,
            )
            s.add(scan)
            s.flush()
            return scan.id

    def finish(
        self,
        scan_id: int,
        status: str,
        findings: Sequence[Finding],
        *,
        observations: str | None = None,
    ) -> None:
        """Record the final status, findings (canonical order) and recorded observations."""
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise NotFoundError("Scan not found")
            scan.status = status
            scan.finished_at = _now()
            if observations is not None:
                scan.observations = observations
            for position, f in enumerate(findings):
                s.add(
                    FindingRecord(
                        scan_id=scan_id,
                        finding_id=f.id,
                        rule_id=f.rule_id,
                        severity=f.severity.value,
                        status=f.status.value,
                        position=position,
                        payload=f.model_dump_json(),
                        reviewed=False,
                    )
                )

    def get(self, scan_id: int) -> Scan:
        """One scan or 404."""
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise NotFoundError("Scan not found")
            return scan

    def findings(self, scan_id: int) -> list[Finding]:
        """Stored findings in canonical order."""
        with self.db.session() as s:
            rows = s.scalars(
                select(FindingRecord)
                .where(FindingRecord.scan_id == scan_id)
                .order_by(FindingRecord.position)
            )
            return [Finding.model_validate_json(r.payload) for r in rows]

    def add_audit(self, scan_id: int, entry: AuditEntry) -> None:
        """Append one probe to the audit log (URL already redacted)."""
        with self.db.session() as s:
            s.add(
                ProbeAudit(
                    scan_id=scan_id,
                    sent_at=entry.sent_at,
                    method=entry.method,
                    url=entry.url,
                    status_code=entry.status,
                    error=(entry.error or None) and entry.error[:200],
                )
            )

    def audit(self, scan_id: int) -> list[ProbeAudit]:
        """Audit entries in send order."""
        with self.db.session() as s:
            return list(
                s.scalars(
                    select(ProbeAudit).where(ProbeAudit.scan_id == scan_id).order_by(ProbeAudit.id)
                )
            )

    def mark_interrupted(self) -> int:
        """Scans left 'running' by a previous process are marked 'interrupted'."""
        with self.db.session() as s:
            result = s.execute(
                update(Scan).where(Scan.status == "running").values(status="interrupted")
            )
            return int(result.rowcount or 0)  # type: ignore[attr-defined]
