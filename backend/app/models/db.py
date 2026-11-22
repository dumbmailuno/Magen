"""SQLAlchemy ORM models.

Deliberately absent: any column for the user-supplied auth header. It lives in memory only
(CLAUDE.md §2). Finding payloads are stored as the redacted Pydantic JSON.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all tables."""


class Target(Base):
    """A host the user has allowlisted and confirmed authorization for."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    #: Explicitly allowlisted loopback/lab target (permits private ranges, CLAUDE.md §7).
    is_local: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Timestamp the user ticked "I own / am authorized to test this host".
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scans: Mapped[list[Scan]] = relationship(back_populates="target")


class Scan(Base):
    """One scan run, with provenance for reproducibility."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    #: Baseline for retest comparisons.
    baseline_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    magen_version: Mapped[str] = mapped_column(String(32), nullable=False)
    commit: Mapped[str] = mapped_column(String(40), nullable=False)
    #: Non-secret scan options (rate limit, request cap, input file names/hashes).
    options: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    #: Recorded, redacted runtime observations (app.runtime.recording) for correlation/replay.
    observations: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[Target | None] = relationship(back_populates="scans")
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    """A finding as produced in a given scan."""

    __tablename__ = "findings"

    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(13), nullable=False)
    #: Canonical order within the scan (see ``sort_findings``).
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class ProbeAudit(Base):
    """Every runtime probe sent, for reproducibility and accountability (CLAUDE.md §7)."""

    __tablename__ = "probe_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    #: Redacted URL (query-string secrets removed).
    url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(200))


class AppSetting(Base):
    """Non-secret user preference (e.g. AI enabled, Ollama model)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[object] = mapped_column(JSON, nullable=False)
