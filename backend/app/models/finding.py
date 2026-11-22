"""Finding schema — the single source of truth (CLAUDE.md §5).

Changing this module requires updating ``frontend/src/lib/types.ts``, the tests, the
committed JSON Schema (``docs/finding.schema.json``) and ``docs/rules.md``.

Reproducibility guarantees implemented here:

* :func:`compute_finding_id` is a pure function of rule id + normalized locations +
  evidence content, with line endings and path separators normalized so that the same
  input yields the same id on Windows and Linux.
* :func:`sort_findings` defines the one canonical output order.
* Evidence text is redacted on construction, so a secret can never reach storage or export.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.core.redaction import redact_text

RULE_ID_PATTERN: Final = r"^[A-Z]{2,5}-[A-Z]{2,5}-\d{3}$"
TITLE_MAX_LENGTH: Final = 200
FINDING_ID_LENGTH: Final = 20

RuleId = Annotated[str, StringConstraints(pattern=RULE_ID_PATTERN)]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-\d+$")]
#: OWASP API Security Top 10 (2023), e.g. ``API8:2023``.
OwaspApiId = Annotated[str, StringConstraints(pattern=r"^API(10|[1-9]):2023$")]


class Severity(StrEnum):
    """Finding severity, lowest to highest."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank, higher is more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Final = {s: i for i, s in enumerate(Severity)}


class FindingStatus(StrEnum):
    """Certainty of a finding, set by the correlation engine."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"


class Source(StrEnum):
    """Where the evidence for a finding came from."""

    STATIC = "static"
    RUNTIME = "runtime"
    CORRELATED = "correlated"


class EvidenceKind(StrEnum):
    """Type of evidence artefact."""

    OPENAPI = "openapi"
    NGINX = "nginx"
    HTTP = "http"
    TLS = "tls"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _normalize_text(value: str) -> str:
    """Normalize line endings and trailing whitespace so hashes are platform-stable."""
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


class Location(_Frozen):
    """Where evidence lives: a file position, a JSON pointer, and/or a URL."""

    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    #: Structural locator. OpenAPI: RFC 6901 JSON pointer (``/paths/~1users/get``).
    #: Nginx: directive path with per-name sibling index (``/http/0/server/1/autoindex/0``).
    pointer: str | None = None
    url: str | None = None

    @field_validator("file")
    @classmethod
    def _posix_path(cls, value: str | None) -> str | None:
        return value.replace("\\", "/") if value is not None else None

    @field_validator("url")
    @classmethod
    def _redact_url(cls, value: str | None) -> str | None:
        return redact_text(value) if value is not None else None

    def key(self) -> str:
        """Canonical string used for sorting (includes line numbers, for reading order)."""
        return "|".join(
            [
                self.file or "",
                f"{self.line or 0:08d}",
                str(self.end_line or ""),
                self.pointer or "",
                self.url or "",
            ]
        )

    def identity_key(self) -> str:
        """Canonical string used for finding ids.

        Line numbers are excluded whenever a structural ``pointer`` exists, so editing
        unrelated parts of a file does not change ids — retest can then tell "persists"
        from "resolved + new". Without a pointer the line is the only locator and is kept.
        """
        line_part = "" if self.pointer is not None else str(self.line or "")
        return "|".join([self.file or "", line_part, self.pointer or "", self.url or ""])


class Evidence(_Frozen):
    """One piece of evidence. All text fields are redacted on construction."""

    kind: EvidenceKind
    location: Location
    excerpt: str
    request: str | None = None
    response: str | None = None

    @field_validator("excerpt", "request", "response")
    @classmethod
    def _redact(cls, value: str | None) -> str | None:
        return redact_text(value) if value is not None else None


class References(_Frozen):
    """Standards mapping. Every rule maps to OWASP API Top 10 (2023) and a CWE if one fits."""

    owasp_api: list[OwaspApiId] = Field(default_factory=list)
    cwe: list[CweId] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class Remediation(_Frozen):
    """Suggested fix. Magen never writes to user files (Option B)."""

    template_fix: str | None = None
    ai_fix: str | None = None
    #: True only if the fix passed the validators (re-parse / ``nginx -t``).
    validated: bool = False


class AiExplanation(_Frozen):
    """AI-generated explanation, with provenance (CLAUDE.md §8). Always labelled in the UI."""

    text: str
    model: str
    prompt_version: str
    generated_at: datetime


class Finding(_Frozen):
    """A single deterministic finding produced by a rule (or the correlation engine)."""

    id: Annotated[str, StringConstraints(pattern=rf"^[0-9a-f]{{{FINDING_ID_LENGTH}}}$")]
    rule_id: RuleId
    title: Annotated[str, StringConstraints(min_length=1, max_length=TITLE_MAX_LENGTH)]
    category: Annotated[str, StringConstraints(min_length=1)]
    severity: Severity
    status: FindingStatus
    source: Source
    evidence: Annotated[list[Evidence], Field(min_length=1)]
    references: References = Field(default_factory=References)
    remediation: Remediation = Field(default_factory=Remediation)
    ai_explanation: AiExplanation | None = None

    @field_validator("title")
    @classmethod
    def _redact_title(cls, value: str) -> str:
        # Titles may quote spec content (URLs, names); never let a secret through.
        return redact_text(value)


def _evidence_digest(evidence: Iterable[Evidence]) -> str:
    """Hash the *stable* parts of evidence (not request/response, which carry dates etc.)."""
    canonical = sorted(
        (e.kind.value, e.location.identity_key(), _normalize_text(e.excerpt)) for e in evidence
    )
    blob = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def compute_finding_id(rule_id: str, evidence: Iterable[Evidence]) -> str:
    """Stable finding id = hash(rule_id + normalized locations + evidence hash)."""
    items = list(evidence)
    locations = "\n".join(sorted(e.location.identity_key() for e in items))
    material = "\0".join([rule_id, locations, _evidence_digest(items)])
    return hashlib.sha256(material.encode()).hexdigest()[:FINDING_ID_LENGTH]


def make_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    status: FindingStatus,
    source: Source,
    evidence: list[Evidence],
    references: References | None = None,
    remediation: Remediation | None = None,
) -> Finding:
    """Construct a :class:`Finding` with its deterministic id filled in."""
    return Finding(
        id=compute_finding_id(rule_id, evidence),
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        status=status,
        source=source,
        evidence=evidence,
        references=references or References(),
        remediation=remediation or Remediation(),
    )


def _sort_key(f: Finding) -> tuple[int, str, str, str]:
    first_location = min(e.location.key() for e in f.evidence)
    return (-f.severity.rank, f.rule_id, first_location, f.id)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Canonical order: severity desc, then rule id, location, id.

    Duplicate ids collapse to the first occurrence.
    """
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    return sorted(unique.values(), key=_sort_key)
