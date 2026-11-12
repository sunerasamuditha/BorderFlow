from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx
from google.protobuf import json_format
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2a.client import ClientConfig, create_client
from a2a.types import AgentCard, Message, Part, Role, SendMessageRequest, StreamResponse, TaskState

from .envelope import ENVELOPE_KEY, build_envelope
from .guard import Decision, FlowGuard, Handle
from .labels import join_all

INTERRUPTED = {TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED}
FAILURES = {TaskState.TASK_STATE_FAILED, TaskState.TASK_STATE_REJECTED, TaskState.TASK_STATE_CANCELED}
CARD_PATH = "/.well-known/agent-card.json"


def part_content(part: Part) -> dict:
    d = json_format.MessageToDict(part)
    d.pop("metadata", None)
    return d


def part_value(part: Part):
    kind = part.WhichOneof("content")
    if kind == "text":
        return part.text
    if kind == "data":
        return json_format.MessageToDict(part.data)
    if kind == "url":
        return part.url
    return bytes(part.raw)


def part_envelope(part: Part) -> Optional[dict]:
    if ENVELOPE_KEY in part.metadata:
        return json_format.MessageToDict(part.metadata)[ENVELOPE_KEY]
    return None


def make_part(value, envelope: Optional[dict] = None) -> Part:
    if isinstance(value, (dict, list)):
        part = Part()
        json_format.ParseDict(value, part.data)
    else:
        part = Part(text=str(value))
    if envelope is not None:
        part.metadata.update({ENVELOPE_KEY: envelope})
    return part


def message_content(parts: list[Part]) -> dict:
    return {"parts": [part_content(p) for p in parts]}


def channel_for_state(state: int, event: str) -> str:
    if state in INTERRUPTED:
        return "interruption"
    if state in FAILURES:
        return "termination"
    if event == "status_update" and state != TaskState.TASK_STATE_COMPLETED:
        return "async"
    return "result"


class HostRouter(httpx.AsyncBaseTransport):
    def __init__(self, apps: dict, wrappers: Optional[dict] = None):
        self.transports = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}
        self.wrappers = wrappers or {}

    def add(self, host: str, app) -> None:
        self.transports[host] = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        transport = self.transports.get(host)
        if transport is None:
            return httpx.Response(404, text=f"unknown host {host}")
        response = await transport.handle_async_request(request)
        wrapper = self.wrappers.get(host)
        if wrapper is not None:
            response = await wrapper(request, response)
        return response


@dataclass
class GuardedResult:
    task_id: str = ""
    context_id: str = ""
    state: str = ""
    handles: list = field(default_factory=list)
    by_channel: dict = field(default_factory=dict)
    denied: Optional[Decision] = None

    def add(self, channel: str, h: Handle) -> None:
        self.handles.append(h)
        self.by_channel.setdefault(channel, []).append(h)

    def texts(self, channel: Optional[str] = None) -> list:
        hs = self.handles if channel is None else self.by_channel.get(channel, [])
        return [h.content for h in hs]


class GuardedA2AClient:
    def __init__(self, guard: FlowGuard, http: httpx.AsyncClient, remote: str, base_url: str, streaming: bool = False):
        self.guard = guard
        self.http = http
        self.remote = remote
        self.base_url = base_url
        self.streaming = streaming
        self._client = None

    async def client(self):
        if self._client is None:
            self._client = await create_client(self.base_url, client_config=ClientConfig(streaming=self.streaming, httpx_client=self.http))
        return self._client

    async def fetch_card(self) -> tuple[AgentCard, list]:
        response = await self.http.get(self.base_url + CARD_PATH)
        card = json_format.ParseDict(response.json(), AgentCard(), ignore_unknown_fields=True)
        handles = [self.guard.ingress(self.remote, card.description, "discovery", note="card.description")]
        for skill in card.skills:
            handles.append(self.guard.ingress(self.remote, skill.description, "discovery", note=f"skill:{skill.id}"))
            for ex in skill.examples:
                handles.append(self.guard.ingress(self.remote, ex, "discovery", note=f"example:{skill.id}"))
        return card, handles

    async def send(self, handles: list, a2a_ctx: Optional[str] = None, task_id: Optional[str] = None, channel: str = "request") -> GuardedResult:
        a2a_ctx = a2a_ctx or str(uuid.uuid4())
        parts = []
        for seq, h in enumerate(handles):
            part = make_part(h.content)
            decision, envelope = self.guard.egress(self.remote, h, channel, a2a_ctx, wire_content=part_content(part), seq=seq)
            if not decision:
                return GuardedResult(denied=decision)
            if envelope is not None:
                part.metadata.update({ENVELOPE_KEY: envelope})
            parts.append(part)
        msg_label = join_all(h.label for h in handles)
        msg = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER, parts=parts, context_id=a2a_ctx)
        if task_id:
            msg.task_id = task_id
        if self.guard.config.enforcing:
            msg.metadata.update({ENVELOPE_KEY: build_envelope(self.guard.keys, msg_label, message_content(parts), "message", a2a_ctx or "")})
        client = await self.client()
        result = GuardedResult(context_id=a2a_ctx)
        async for response in client.send_message(SendMessageRequest(message=msg)):
            self._absorb(response, result)
        return result

    def _ingest_parts(self, parts, channel: str, result: GuardedResult, note: str) -> None:
        for part in parts:
            h = self.guard.ingress(self.remote, part_value(part), channel, part_envelope(part), result.context_id or None, part_content(part), note=note)
            result.add(channel, h)

    def _absorb(self, response: StreamResponse, result: GuardedResult) -> None:
        kind = response.WhichOneof("payload")
        if kind == "task":
            task = response.task
            result.task_id, result.context_id = task.id, task.context_id
            result.state = TaskState.Name(task.status.state)
            if task.status.HasField("message"):
                self._ingest_parts(task.status.message.parts, channel_for_state(task.status.state, "task"), result, "status.message")
            for art in task.artifacts:
                self._ingest_parts(art.parts, "result", result, f"artifact:{art.name}")
        elif kind == "message":
            result.context_id = result.context_id or response.message.context_id
            self._ingest_parts(response.message.parts, "result", result, "message")
        elif kind == "status_update":
            ev = response.status_update
            result.task_id, result.context_id = ev.task_id, ev.context_id
            result.state = TaskState.Name(ev.status.state)
            if ev.status.HasField("message"):
                self._ingest_parts(ev.status.message.parts, channel_for_state(ev.status.state, "status_update"), result, "status_update")
        elif kind == "artifact_update":
            ev = response.artifact_update
            result.task_id, result.context_id = ev.task_id, ev.context_id
            self._ingest_parts(ev.artifact.parts, "result", result, f"artifact_update:{ev.artifact.name}")


def push_webhook_app(guard: FlowGuard, tokens: dict, inbox: list) -> Starlette:
    async def receive(request: Request):
        principal = tokens.get(request.headers.get("x-a2a-notification-token", ""))
        if principal is None:
            return JSONResponse({"error": "unknown token"}, status_code=401)
        payload = json_format.ParseDict(await request.json(), StreamResponse(), ignore_unknown_fields=True)
        kind = payload.WhichOneof("payload")
        if kind == "status_update" and payload.status_update.status.HasField("message"):
            for part in payload.status_update.status.message.parts:
                inbox.append(guard.ingress(principal, part_value(part), "async", part_envelope(part), payload.status_update.context_id or None, part_content(part), note="push"))
        return JSONResponse({"ok": True})

    return Starlette(routes=[Route("/push", receive, methods=["POST"])])
