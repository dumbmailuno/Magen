"""AI assistant: explanations and fix suggestions. Optional; never decides findings.

Guarantees (tested in tests/test_ai.py):
* Only ``ai_explanation`` / ``remediation.ai_fix`` of a stored finding can change — never
  its id, status, severity, evidence or the deterministic template.
* Output is schema-constrained, Pydantic-validated, retried once, then replaced by the
  deterministic template explanation (``fallback``).
* Every stored output records the model (name@digest) and the prompt version.
* AI fixes may rewrite only the finding's own lines and must pass the same validator as
  template fixes; unvalidated output is reported as such.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from pydantic import ValidationError

from app.ai.client import (
    AiResponseError,
    AiUnavailableError,
    ModelInfo,
    OllamaClient,
    OllamaStatus,
    PullProgress,
    require_loopback,
)
from app.ai.guard import clean_block, clean_output, looks_like_injection
from app.ai.prompts import (
    EXPLAIN_SYSTEM,
    EXPLAIN_VERSION,
    FIX_SYSTEM,
    FIX_VERSION,
    explain_prompt,
    fix_prompt,
)
from app.ai.schemas import ExplanationOut, FixOut, schema_of
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.finding import AiExplanation, Finding
from app.remediation.diff import unified_diff
from app.remediation.edits import Edit, apply_edits
from app.remediation.service import corrected_name
from app.remediation.validate import Kind, Validation, analyze, validate
from app.retest.compare import canonical_filename
from app.retest.sessions import require_session
from app.rules.catalog import load_rules
from app.rules.registry import registry
from app.storage.database import Database
from app.storage.repositories import ScanRepository, SettingsRepository, update_finding

log = logging.getLogger(__name__)

MAX_FIX_LINES = 60
ResultState = Literal["ready", "unavailable", "error"]


@dataclass(frozen=True)
class AiConfig:
    """User-adjustable AI preferences (no secrets)."""

    enabled: bool
    url: str
    model: str


@dataclass
class ExplainResult:
    """Explanation outcome; ``fallback`` is the deterministic template explanation."""

    state: ResultState
    finding: Finding
    fallback: str
    message: str | None = None
    injection_suspected: bool = False
    cached: bool = False


@dataclass
class FixResult:
    """AI fix outcome (a corrected copy for review; never applied)."""

    state: ResultState
    fallback: str
    message: str | None = None
    injection_suspected: bool = False
    finding: Finding | None = None
    explanation: str | None = None
    diff: str = ""
    patched_content: str = ""
    patched_filename: str = ""
    validated: bool = False
    validation: Validation | None = None
    model: str = ""
    prompt_version: str = FIX_VERSION


class AiService:
    """Owns AI configuration, model status, downloads and generation."""

    def __init__(
        self,
        db: Database,
        *,
        default_url: str,
        default_model: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.db = db
        self.settings = SettingsRepository(db)
        self.default_url = default_url
        self.default_model = default_model
        self.transport = transport
        self.pull_progress: PullProgress | None = None
        self._pull_task: asyncio.Task[None] | None = None

    # ---- configuration & status -------------------------------------------------------

    def config(self) -> AiConfig:
        """Current preferences (defaults from MAGEN_* settings)."""
        return AiConfig(
            enabled=bool(self.settings.get("ai.enabled", True)),
            url=str(self.settings.get("ai.url", self.default_url)),
            model=str(self.settings.get("ai.model", self.default_model)),
        )

    def update(self, *, enabled: bool | None, url: str | None, model: str | None) -> AiConfig:
        """Change preferences; the URL must stay loopback."""
        if url is not None:
            try:
                self.settings.set("ai.url", require_loopback(url))
            except ValueError as exc:
                raise ValidationFailedError(str(exc)) from exc
        if model is not None:
            if not model.strip() or len(model) > 200:
                raise ValidationFailedError("Enter a model name, e.g. qwen3:4b")
            self.settings.set("ai.model", model.strip())
        if enabled is not None:
            self.settings.set("ai.enabled", enabled)
        return self.config()

    def client(self) -> OllamaClient:
        """Client for the configured (loopback) URL."""
        return OllamaClient(self.config().url, transport=self.transport)

    @staticmethod
    def _find_model(models: list[ModelInfo], name: str) -> ModelInfo | None:
        wanted = {name, f"{name}:latest"} if ":" not in name else {name}
        return next((m for m in models if m.name in wanted), None)

    async def status(self) -> OllamaStatus:
        """disabled / downloading / not_running / model_missing / ready."""
        cfg = self.config()
        base = OllamaStatus(state="disabled", url=cfg.url, model=cfg.model, pull=self.pull_progress)
        if not cfg.enabled:
            return base
        if self.pull_progress is not None and not self.pull_progress.done:
            base.state = "downloading"
            return base
        client = self.client()
        try:
            base.version = await client.version()
            models = await client.models()
        except AiUnavailableError:
            base.state = "not_running"
            return base
        base.models = [m.name for m in models]
        base.state = "ready" if self._find_model(models, cfg.model) else "model_missing"
        return base

    def start_pull(self, model: str | None = None) -> PullProgress:
        """Download the configured (or given) model in the background."""
        if self._pull_task is not None and not self._pull_task.done():
            raise ValidationFailedError("A model download is already running")
        name = model or self.config().model
        progress = PullProgress(model=name)
        self.pull_progress = progress
        self._pull_task = asyncio.create_task(self.client().pull(name, progress))
        return progress

    async def _model_tag(self) -> str:
        cfg = self.config()
        found = self._find_model(await self.client().models(), cfg.model)
        if found is None:
            raise AiUnavailableError(f"Model {cfg.model} is not installed")
        return found.tag

    # ---- helpers ------------------------------------------------------------------------

    def _load(self, session_id: int, finding_id: str) -> tuple[ScanRepository, Finding]:
        repo = ScanRepository(self.db)
        require_session(repo, session_id)
        finding = next((f for f in repo.findings(session_id) if f.id == finding_id), None)
        if finding is None:
            raise NotFoundError("Finding not found in this session")
        return repo, finding

    @staticmethod
    def _rule_text(f: Finding) -> tuple[str, str, str]:
        load_rules()
        rule = registry.get(f.rule_id)
        if rule is None:  # pragma: no cover - every stored finding comes from a registered rule
            return f.title, f.category, f.remediation.template_fix or ""
        return rule.title, rule.description, rule.remediation_template

    @staticmethod
    def fallback_for(description: str, template: str) -> str:
        """Deterministic explanation shown whenever AI output is unavailable or invalid."""
        return f"{description}\n\nRecommended fix:\n{template}"

    async def _ask(self, system: str, user: str, schema_cls: type[Any]) -> Any:
        """Two attempts at schema-valid output; the second failure is reported."""
        last: Exception | None = None
        cfg = self.config()
        for _ in range(2):
            raw = await self.client().chat_json(cfg.model, system, user, schema_of(schema_cls))
            try:
                return schema_cls.model_validate_json(raw)
            except ValidationError as exc:
                last = exc
                log.info(
                    "ai output failed validation; retrying", extra={"errors": exc.error_count()}
                )
        raise AiResponseError("The model's answer did not match the required format") from last

    # ---- explanation --------------------------------------------------------------------

    async def explain(
        self, session_id: int, finding_id: str, *, force: bool = False
    ) -> ExplainResult:
        """Explain one stored finding, caching the result on the finding."""
        _, finding = self._load(session_id, finding_id)
        title, description, template = self._rule_text(finding)
        fallback = self.fallback_for(description, template)
        suspected = looks_like_injection(
            "\n".join([finding.title, *(e.excerpt for e in finding.evidence)])
        )
        if not self.config().enabled:
            return ExplainResult(
                "unavailable", finding, fallback, "AI is turned off in Settings", suspected
            )
        cached = finding.ai_explanation
        if cached is not None and cached.prompt_version == EXPLAIN_VERSION and not force:
            return ExplainResult("ready", finding, fallback, None, suspected, cached=True)
        try:
            tag = await self._model_tag()
            out: ExplanationOut = await self._ask(
                EXPLAIN_SYSTEM,
                explain_prompt(finding, title, description, template),
                ExplanationOut,
            )
        except AiUnavailableError as exc:
            return ExplainResult("unavailable", finding, fallback, str(exc), suspected)
        except AiResponseError as exc:
            return ExplainResult("error", finding, fallback, str(exc), suspected)
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(out.steps, 1))
        text = clean_output(f"{out.summary}\n\nImpact: {out.impact}\n\nSteps:\n{steps}")
        updated = finding.model_copy(
            update={
                "ai_explanation": AiExplanation(
                    text=text,
                    model=tag,
                    prompt_version=EXPLAIN_VERSION,
                    generated_at=datetime.now(tz=UTC),
                )
            }
        )
        update_finding(self.db, session_id, updated)
        return ExplainResult(
            "ready", updated, fallback, None, suspected or out.evidence_contains_instructions
        )

    # ---- fix ----------------------------------------------------------------------------

    async def fix(
        self, session_id: int, finding_id: str, *, kind: Kind, filename: str, content: str
    ) -> FixResult:
        """Ask the model to rewrite the finding's own lines; validate like a template fix."""
        _, finding = self._load(session_id, finding_id)
        title, description, template = self._rule_text(finding)
        fallback = self.fallback_for(description, template)
        loc = finding.evidence[0].location
        if loc.file is None or loc.line is None:
            raise ValidationFailedError("AI fixes are only available for findings with file lines")
        if canonical_filename(loc.file) != canonical_filename(filename.replace("\\", "/")):
            raise ValidationFailedError("This finding belongs to a different file")
        if finding.id not in {f.id for f in analyze(kind, content, filename)}:
            raise ValidationFailedError("The file changed since the scan; rescan first")
        start, end = loc.line, loc.end_line or loc.line
        if end - start + 1 > MAX_FIX_LINES:
            raise ValidationFailedError("The affected block is too large for an AI fix")
        original_lines = content.replace("\r\n", "\n").split("\n")[start - 1 : end]
        suspected = looks_like_injection("\n".join(original_lines))
        if not self.config().enabled:
            return FixResult("unavailable", fallback, "AI is turned off in Settings", suspected)
        try:
            tag = await self._model_tag()
            out: FixOut = await self._ask(
                FIX_SYSTEM,
                fix_prompt(finding, title, description, template, original_lines, kind),
                FixOut,
            )
        except AiUnavailableError as exc:
            return FixResult("unavailable", fallback, str(exc), suspected)
        except AiResponseError as exc:
            return FixResult("error", fallback, str(exc), suspected)
        replacement = clean_block(out.replacement)
        if replacement == original_lines or not "".join(replacement).strip():
            return FixResult("error", fallback, "The model did not propose a change", suspected)
        patched = apply_edits(content, [Edit(finding.id, start, end, tuple(replacement))]).text
        validation = validate(kind, filename, content, patched, [finding])
        updated = finding.model_copy(
            update={
                "remediation": finding.remediation.model_copy(
                    update={"ai_fix": "\n".join(replacement)}
                )
            }
        )
        update_finding(self.db, session_id, updated)
        return FixResult(
            state="ready",
            fallback=fallback,
            injection_suspected=suspected or out.evidence_contains_instructions,
            finding=updated,
            explanation=clean_output(out.explanation),
            diff=unified_diff(content, patched, filename),
            patched_content=patched,
            patched_filename=corrected_name(filename),
            validated=validation.is_validated(finding.id),
            validation=validation,
            model=tag,
        )
