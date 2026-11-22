"""Structured output contracts. The JSON Schema is sent to Ollama; Pydantic re-validates."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Short = Annotated[str, StringConstraints(min_length=1, max_length=600, strip_whitespace=True)]
Step = Annotated[str, StringConstraints(min_length=1, max_length=300, strip_whitespace=True)]


class ExplanationOut(BaseModel):
    """What the model must return for an explanation."""

    model_config = ConfigDict(extra="forbid")

    summary: Short
    impact: Short
    steps: Annotated[list[Step], Field(min_length=1, max_length=6)]
    evidence_contains_instructions: bool = False


class FixOut(BaseModel):
    """What the model must return for a fix of the finding's own lines."""

    model_config = ConfigDict(extra="forbid")

    replacement: Annotated[str, StringConstraints(max_length=4000)]
    explanation: Short
    evidence_contains_instructions: bool = False


def schema_of(model: type[BaseModel]) -> dict[str, Any]:
    """JSON Schema for Ollama's ``format`` parameter."""
    return model.model_json_schema()
