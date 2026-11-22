"""Ollama client (local only). The only code in Magen that talks to a language model.

The URL is validated to be loopback at configuration time (``Settings.ollama_url``) and
again here, so a cloud endpoint can never be reached by accident (CLAUDE.md §8).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Final, Literal

import httpx

log = logging.getLogger(__name__)

LOOPBACK_PREFIXES: Final = ("http://127.0.0.1", "http://localhost", "http://[::1]")
TEMPERATURE: Final = 0.1
SEED: Final = 7
STATUS_TIMEOUT: Final = httpx.Timeout(3.0)
GENERATE_TIMEOUT: Final = httpx.Timeout(120.0, connect=3.0)

AiState = Literal["disabled", "not_running", "model_missing", "downloading", "ready"]


class AiUnavailableError(Exception):
    """Ollama is not reachable or the model is not installed."""


class AiResponseError(Exception):
    """Ollama answered, but not with usable content."""


@dataclass(frozen=True)
class ModelInfo:
    """An installed model."""

    name: str
    digest: str

    @property
    def tag(self) -> str:
        """Name plus short digest, recorded with every output for reproducibility."""
        return f"{self.name}@{self.digest[:12]}" if self.digest else self.name


@dataclass
class PullProgress:
    """State of an in-progress ``ollama pull``."""

    model: str
    status: str = "starting"
    completed: int = 0
    total: int = 0
    error: str | None = None
    done: bool = False

    @property
    def percent(self) -> int | None:
        """0 to 100 once the size is known."""
        return int(self.completed * 100 / self.total) if self.total else None


@dataclass
class OllamaStatus:
    """What the UI needs to pick the right AI panel state."""

    state: AiState
    url: str
    model: str
    version: str | None = None
    models: list[str] = field(default_factory=list)
    pull: PullProgress | None = None


def require_loopback(url: str) -> str:
    """Refuse anything but a local Ollama."""
    if not url.startswith(LOOPBACK_PREFIXES):
        raise ValueError("Ollama URL must be a loopback address (cloud AI is disabled)")
    return url.rstrip("/")


class OllamaClient:
    """Thin async wrapper over Ollama's HTTP API."""

    def __init__(self, url: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.url = require_loopback(url)
        self._transport = transport

    def _client(self, timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.url, transport=self._transport, timeout=timeout, trust_env=False
        )

    async def version(self) -> str:
        """Ollama server version (raises AiUnavailableError if not running)."""
        try:
            async with self._client(STATUS_TIMEOUT) as c:
                res = await c.get("/api/version")
                res.raise_for_status()
                return str(res.json().get("version", ""))
        except (httpx.HTTPError, ValueError) as exc:
            raise AiUnavailableError("Ollama is not running") from exc

    async def models(self) -> list[ModelInfo]:
        """Installed models, sorted by name."""
        try:
            async with self._client(STATUS_TIMEOUT) as c:
                res = await c.get("/api/tags")
                res.raise_for_status()
                data = res.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AiUnavailableError("Ollama is not running") from exc
        items = data.get("models", []) if isinstance(data, dict) else []
        return sorted(
            (ModelInfo(str(m.get("name", "")), str(m.get("digest", ""))) for m in items),
            key=lambda m: m.name,
        )

    async def chat_json(self, model: str, system: str, user: str, schema: dict[str, Any]) -> str:
        """One non-streaming chat turn constrained to ``schema``; returns the raw content."""
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": schema,
            "think": False,
            "options": {"temperature": TEMPERATURE, "seed": SEED, "num_ctx": 8192},
        }
        try:
            async with self._client(GENERATE_TIMEOUT) as c:
                res = await c.post("/api/chat", json=body)
        except httpx.TimeoutException as exc:
            raise AiResponseError("The model took too long to answer") from exc
        except httpx.HTTPError as exc:
            raise AiUnavailableError("Ollama is not running") from exc
        if res.status_code == 404:
            raise AiUnavailableError(f"Model {model} is not installed")
        if res.status_code >= 400:
            raise AiResponseError(f"Ollama returned HTTP {res.status_code}")
        try:
            content = res.json()["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AiResponseError("Unexpected response from Ollama") from exc
        if not isinstance(content, str):
            raise AiResponseError("Unexpected response from Ollama")
        return content

    async def pull(self, model: str, progress: PullProgress) -> None:
        """Download a model, updating ``progress`` from Ollama's NDJSON stream."""
        try:
            async with (
                self._client(httpx.Timeout(None, connect=3.0)) as c,
                c.stream("POST", "/api/pull", json={"model": model, "stream": True}) as res,
            ):
                if res.status_code >= 400:
                    progress.error = f"Ollama returned HTTP {res.status_code}"
                    return
                async for line in res.aiter_lines():
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    if "error" in event:
                        progress.error = str(event["error"])
                        return
                    progress.status = str(event.get("status", progress.status))
                    progress.completed = int(event.get("completed", progress.completed) or 0)
                    progress.total = int(event.get("total", progress.total) or 0)
        except (httpx.HTTPError, ValueError) as exc:
            progress.error = "Download failed: Ollama is not reachable"
            log.info("ollama pull failed", extra={"error_type": type(exc).__name__})
        finally:
            progress.done = True
