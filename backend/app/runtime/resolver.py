"""DNS resolution behind an interface so tests never touch real DNS."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Protocol

from app.core.safety import IPAddress


class Resolver(Protocol):
    """Resolves a host to IP addresses."""

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        """All addresses for ``host``."""
        ...


class SystemResolver:
    """``getaddrinfo`` on the event loop's executor."""

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        """All A/AAAA addresses (IP literals resolve to themselves)."""
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
