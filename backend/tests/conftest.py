from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings
from app.main import create_app

TEST_TOKEN = "t" * 48


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(session_token=SecretStr(TEST_TOKEN), data_dir=tmp_path)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), headers={"X-Magen-Token": TEST_TOKEN}) as c:
        yield c


@pytest.fixture
def anon_client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c
