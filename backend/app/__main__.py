"""Entry point used by Electron: ``python -m app``.

Configuration comes from ``MAGEN_*`` environment variables. The bind address is always
127.0.0.1 and is not configurable.
"""

from __future__ import annotations

import uvicorn

from app.core.config import BIND_HOST, get_settings
from app.main import create_app


def main() -> None:
    """Run the API server on loopback."""
    settings = get_settings()
    uvicorn.run(
        create_app(settings),
        host=BIND_HOST,
        port=settings.port,
        log_config=None,  # our JSON logging is configured in create_app
        access_log=False,  # probe/request auditing is done explicitly, with redaction
    )


if __name__ == "__main__":
    main()
