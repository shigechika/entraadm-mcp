"""Tool exceptions must reach the model with their message on mcp 2.x."""

import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from entraadm_mcp.server import _Server


class _DomainError(Exception):
    pass


def _server():
    srv = _Server("t")

    @srv.tool()
    def boom(x: int) -> str:
        """Raise a domain error."""
        raise _DomainError(f"bad input {x}")

    @srv.tool()
    async def aboom() -> str:
        """Raise from a coroutine."""
        raise _DomainError("async failure")

    @srv.tool()
    def fine(x: int) -> str:
        """Return normally."""
        return f"ok {x}"

    return srv


def test_sync_tool_error_message_reaches_the_caller():
    with pytest.raises(ToolError, match="bad input 7"):
        asyncio.run(_server().call_tool("boom", {"x": 7}))


def test_async_tool_error_message_reaches_the_caller():
    with pytest.raises(ToolError, match="async failure"):
        asyncio.run(_server().call_tool("aboom", {}))


def test_a_normal_return_is_untouched():
    result = asyncio.run(_server().call_tool("fine", {"x": 3}))
    assert "ok 3" in str(result)
