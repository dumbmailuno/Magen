"""Runtime scan orchestration: one asyncio task per scan, cancellable at any point."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from app import __version__
from app.core.errors import ValidationFailedError
from app.core.redaction import redact_text
from app.core.safety import (
    AuthorizedTarget,
    BudgetExceededError,
    RateLimiter,
    RequestBudget,
    UnsafeTargetError,
    require_same_host,
)
from app.models.finding import Finding, sort_findings
from app.rules.base import RuleTarget
from app.rules.catalog import load_rules
from app.rules.registry import registry
from app.runtime.client import AuditEntry, AuthHeader, SafeHttpClient
from app.runtime.observations import RuntimeObservations
from app.runtime.probes import collect, plan_size
from app.runtime.resolver import Resolver, SystemResolver
from app.storage.repositories import ScanRepository
from app.version import commit_hash

log = logging.getLogger(__name__)

#: Statuses after which a scan never changes again.
FINAL = frozenset({"done", "failed", "cancelled"})


@dataclass
class ScanJob:
    """In-memory state of a runtime scan (the auth header lives only in ``auth``)."""

    id: int
    target: AuthorizedTarget
    base_url: str  # redacted copy for display
    total: int
    status: str = "running"
    done: int = 0
    current: str = "Starting"
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    finished_at: datetime | None = None
    task: asyncio.Task[None] | None = None


def run_runtime_rules(obs: RuntimeObservations) -> list[Finding]:
    """Pure step: observations → canonical findings."""
    load_rules()
    findings: list[Finding] = []
    for rule_cls in registry.for_target(RuleTarget.RUNTIME):
        findings.extend(rule_cls().check(obs))
    return sort_findings(findings)


class ScanManager:
    """Starts, tracks and stops runtime scans. One running scan at a time."""

    def __init__(
        self,
        scans: ScanRepository,
        *,
        resolver: Resolver | None = None,
        transport_factory: Callable[[], httpx.AsyncBaseTransport | None] = lambda: None,
    ) -> None:
        self.scans = scans
        self.resolver = resolver or SystemResolver()
        self.transport_factory = transport_factory
        self.jobs: dict[int, ScanJob] = {}

    def running(self) -> ScanJob | None:
        """The active scan, if any."""
        return next((j for j in self.jobs.values() if j.status not in FINAL), None)

    def start(
        self,
        target: AuthorizedTarget,
        base_url: str,
        *,
        auth: AuthHeader | None,
        rate: float,
        cap: int,
    ) -> ScanJob:
        """Validate and launch a scan task. Raises before any request if anything is off."""
        if self.running() is not None:
            raise ValidationFailedError("A runtime scan is already running; stop it first")
        require_same_host(target, base_url)
        secrets = (auth.value.get_secret_value(),) if auth else ()
        shown_url = redact_text(base_url, secrets)
        options: dict[str, object] = {
            "kind": "runtime",
            "base_url": shown_url,
            "rate_per_second": rate,
            "request_cap": cap,
            # Only the header *name* is stored, never its value.
            "auth_header_name": auth.name if auth else None,
        }
        scan_id = self.scans.create(
            target_id=target.id, options=options, version=__version__, commit=commit_hash()
        )
        job = ScanJob(id=scan_id, target=target, base_url=shown_url, total=plan_size(base_url))
        self.jobs[scan_id] = job
        job.task = asyncio.create_task(self._run(job, base_url, auth, rate, cap))
        return job

    def stop(self, scan_id: int) -> ScanJob:
        """Cancel the task; in-flight requests are aborted."""
        job = self.jobs.get(scan_id)
        if job is None:
            raise ValidationFailedError("Scan is not running in this session")
        if job.status not in FINAL and job.task is not None:
            job.status = "cancelling"
            job.task.cancel()
        return job

    async def _run(
        self, job: ScanJob, base_url: str, auth: AuthHeader | None, rate: float, cap: int
    ) -> None:
        obs = RuntimeObservations(target_host=job.target.host, base_url=job.base_url)

        async def audit(entry: AuditEntry) -> None:
            self.scans.add_audit(job.id, entry)

        async def progress(done: int, total: int, label: str) -> None:
            job.done, job.total, job.current = done, total, redact_text(label)

        client = SafeHttpClient(
            job.target,
            resolver=self.resolver,
            budget=RequestBudget(cap),
            limiter=RateLimiter(rate),
            audit=audit,
            auth=auth,
            transport=self.transport_factory(),
        )
        status = "done"
        try:
            await collect(client, base_url, obs, progress)
        except asyncio.CancelledError:
            status = "cancelled"
            job.notes.append("Stopped by user; findings are from the probes completed so far.")
        except UnsafeTargetError as exc:
            status, job.error = "failed", exc.message
        except BudgetExceededError as exc:  # pragma: no cover - collect() absorbs these
            job.notes.append(exc.message)
        except Exception:
            log.exception("runtime scan failed", extra={"scan_id": job.id})
            status, job.error = "failed", "Unexpected error during the scan"
        finally:
            await client.aclose()
        if obs.skipped:
            job.notes.append(
                f"Request cap reached: {len(obs.skipped)} probe(s) skipped "
                f"({', '.join(obs.skipped)})."
            )
        job.findings = run_runtime_rules(obs) if status != "failed" else []
        self.scans.finish(job.id, status, job.findings)
        job.status, job.finished_at = status, datetime.now(tz=UTC)
        job.done = job.total if status == "done" else job.done
        log.info(
            "runtime scan finished",
            extra={"scan_id": job.id, "status": status, "findings": len(job.findings)},
        )
