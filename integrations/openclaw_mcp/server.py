"""Dependency-free MCP 2024/2025 stdio server with one read-only tool."""

from __future__ import annotations

import json
import sys
from typing import Any, IO, Mapping

from .agentguard_client import AgentGuardClient, AgentGuardClientError


SERVER_VERSION = "0.1.0"
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
}
MAX_MESSAGE_CHARS = 1024 * 1024
TOOL_NAME = "list_notices"


TOOL_DEFINITION: dict[str, Any] = {
    "name": TOOL_NAME,
    "title": "查询内部公告（只读）",
    "description": (
        "通过 AgentGuard 的权限、票据、安全内核和审计链查询内部公告；"
        "不能直连数据库，不提供写入、删除、付款、发布或运维能力。"
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 20,
                "description": "最多返回的公告条数",
            }
        },
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "reason_code": {"type": "string"},
            "row_count": {"type": "integer"},
            "rows": {"type": "array"},
            "side_effect": {"const": False},
        },
        "required": ["status", "reason_code", "row_count", "rows", "side_effect"],
        "additionalProperties": False,
    },
    "annotations": {
        "title": "AgentGuard 只读公告查询",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


def _response(message_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": dict(result)}


def _error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }


def _safe_rows(business_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = business_result.get("rows", [])
    if not isinstance(rows, list):
        return []
    safe: list[dict[str, Any]] = []
    allowed = ("id", "title", "department", "published_at")
    for item in rows[:100]:
        if not isinstance(item, Mapping):
            continue
        safe.append({key: item[key] for key in allowed if key in item})
    return safe


class McpServer:
    """Small protocol adapter; contains no policy or business execution logic."""

    def __init__(self, client: AgentGuardClient) -> None:
        self.client = client
        self.initialized = False

    def _initialize(self, message_id: Any, params: Any) -> dict[str, Any]:
        requested = params.get("protocolVersion", "") if isinstance(params, Mapping) else ""
        negotiated = (
            str(requested)
            if str(requested) in SUPPORTED_PROTOCOL_VERSIONS
            else MCP_PROTOCOL_VERSION
        )
        self.initialized = True
        return _response(
            message_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "agentguard-openclaw-readonly",
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "仅提供只读公告查询；所有实际调用必须经过 AgentGuard。"
                ),
            },
        )

    def _call_tool(self, message_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, Mapping):
            return _error(message_id, -32602, "tools/call params 必须是对象")
        if params.get("name") != TOOL_NAME:
            return _error(message_id, -32602, "未知或未授权的工具")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            return _error(message_id, -32602, "arguments 必须是对象")
        if set(arguments) - {"limit"}:
            return _error(message_id, -32602, "包含未允许的工具参数")
        limit = arguments.get("limit", 20)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            return _error(message_id, -32602, "limit 必须是 1 到 100 的整数")
        try:
            gateway_result = self.client.list_notices(limit)
        except AgentGuardClientError as exc:
            return _response(
                message_id,
                {
                    "content": [{"type": "text", "text": f"调用未执行：{exc.code}"}],
                    "isError": True,
                    "structuredContent": {
                        "status": "blocked",
                        "reason_code": exc.code,
                        "row_count": 0,
                        "rows": [],
                        "side_effect": False,
                    },
                },
            )

        status = str(gateway_result.get("status", "blocked"))
        reason_code = str(gateway_result.get("reason_code", "MCP_G006_UNSAFE_RESPONSE"))
        http_status = gateway_result.get("_agentguard_http_status")
        if status != "executed_isolated" or http_status != 200:
            if status == "executed_isolated":
                status = "blocked"
                reason_code = "MCP_G008_HTTP_STATUS_MISMATCH"
            return _response(
                message_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": f"AgentGuard 未放行或未执行：{reason_code}",
                        }
                    ],
                    "isError": True,
                    "structuredContent": {
                        "status": status,
                        "reason_code": reason_code,
                        "row_count": 0,
                        "rows": [],
                        "side_effect": False,
                    },
                },
            )
        receipt = gateway_result.get("receipt")
        business = receipt.get("business_result") if isinstance(receipt, Mapping) else None
        if not isinstance(business, Mapping) or business.get("side_effect") is not False:
            return _response(
                message_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": "AgentGuard 未返回可验证的只读业务结果",
                        }
                    ],
                    "isError": True,
                    "structuredContent": {
                        "status": "blocked",
                        "reason_code": "MCP_G007_READONLY_RESULT_REQUIRED",
                        "row_count": 0,
                        "rows": [],
                        "side_effect": False,
                    },
                },
            )
        rows = _safe_rows(business)
        output = {
            "status": "executed_isolated",
            "reason_code": reason_code,
            "row_count": len(rows),
            "rows": rows,
            "side_effect": False,
        }
        return _response(
            message_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(output, ensure_ascii=False, separators=(",", ":")),
                    }
                ],
                "structuredContent": output,
                "isError": False,
            },
        )

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, Mapping) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "无效 JSON-RPC 请求")
        message_id = message.get("id")
        is_notification = "id" not in message
        method = message.get("method")
        if not isinstance(method, str):
            return None if is_notification else _error(message_id, -32600, "缺少 method")
        if method == "notifications/initialized":
            return None
        if method == "notifications/cancelled":
            return None
        if is_notification:
            return None
        if method == "initialize":
            return self._initialize(message_id, message.get("params", {}))
        if method == "ping":
            return _response(message_id, {})
        if not self.initialized:
            return _error(message_id, -32002, "MCP 会话尚未 initialize")
        if method == "tools/list":
            return _response(message_id, {"tools": [TOOL_DEFINITION]})
        if method == "tools/call":
            return self._call_tool(message_id, message.get("params", {}))
        return _error(message_id, -32601, "方法不存在")


def serve_stdio(server: McpServer, reader: IO[str] | None = None, writer: IO[str] | None = None) -> int:
    """Serve newline-delimited UTF-8 JSON-RPC. Protocol output is stdout only.

    Windows pipes otherwise inherit the active console code page (often GBK),
    while MCP requires UTF-8 on the wire.  Reconfigure only the real process
    streams; injected text streams used by tests are left untouched.
    """

    if reader is None and hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    if writer is None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="\n")

    source = sys.stdin if reader is None else reader
    target = sys.stdout if writer is None else writer
    while True:
        line = source.readline(MAX_MESSAGE_CHARS + 1)
        if line == "":
            return 0
        if len(line) > MAX_MESSAGE_CHARS:
            while line and not line.endswith("\n"):
                line = source.readline(MAX_MESSAGE_CHARS + 1)
            reply = _error(None, -32600, "MCP 消息超过 1 MiB")
        else:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                reply = _error(None, -32700, "JSON 解析失败")
            else:
                try:
                    reply = server.handle(message)
                except Exception as exc:  # fail closed without leaking internals
                    print(f"internal MCP error: {type(exc).__name__}", file=sys.stderr)
                    reply = _error(message.get("id") if isinstance(message, Mapping) else None, -32603, "内部错误，调用未执行")
        if reply is not None:
            target.write(json.dumps(reply, ensure_ascii=False, separators=(",", ":")) + "\n")
            target.flush()
