"""Allowlist endpoints. Adding a target requires an explicit authorization confirmation."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from app.core.errors import ValidationFailedError
from app.core.safety import is_internal, is_metadata, normalize_host
from app.storage.repositories import TargetRepository

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetIn(BaseModel):
    """New allowlist entry."""

    host: str = Field(min_length=1, max_length=253)
    #: Local lab target: allows loopback/private addresses (never cloud metadata).
    is_local: bool = False
    #: The user ticked "I own this host or have written permission to test it".
    authorization_confirmed: Literal[True]


class TargetOut(BaseModel):
    """Allowlist entry."""

    id: int
    host: str
    is_local: bool
    authorized_at: datetime
    created_at: datetime


def _repo(request: Request) -> TargetRepository:
    return TargetRepository(request.app.state.db)


def _out(t: object) -> TargetOut:
    return TargetOut.model_validate(t, from_attributes=True)


@router.get("")
def list_targets(request: Request) -> list[TargetOut]:
    """All allowlisted targets."""
    return [_out(t) for t in _repo(request).list()]


@router.post("", status_code=201)
def add_target(body: TargetIn, request: Request) -> TargetOut:
    """Allowlist a host and record the authorization timestamp."""
    host = normalize_host(body.host)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and is_metadata(ip):
        raise ValidationFailedError("Cloud metadata addresses can never be scanned")
    if ip is not None and is_internal(ip) and not body.is_local:
        raise ValidationFailedError(
            f"{host} is an internal address: mark it as a local lab target to scan it"
        )
    return _out(_repo(request).add(host, is_local=body.is_local))


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, request: Request) -> Response:
    """Remove a host from the allowlist."""
    _repo(request).delete(target_id)
    return Response(status_code=204)
