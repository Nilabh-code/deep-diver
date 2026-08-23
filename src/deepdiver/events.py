from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class Event:
    kind: str          # "tool" | "agent" | "finding" | "phase" | "error" | "status" | "log"
    agent: str
    message: str
    data: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(
            {"id": self.id, "kind": self.kind, "agent": self.agent,
             "message": self.message, "data": self.data, "ts": self.ts}
        )


class EventBus:
    """Fan-out event bus: keeps a ring buffer, pushes to SSE subscribers."""

    def __init__(self, ring_size: int = 2000):
        self.ring: list[Event] = []
        self.ring_size = ring_size
        self.subs: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def publish(self, kind: str, agent: str, message: str, data: dict | None = None):
        ev = Event(kind=kind, agent=agent, message=message, data=data or {})
        async with self._lock:
            self.ring.append(ev)
            if len(self.ring) > self.ring_size:
                del self.ring[: len(self.ring) - self.ring_size]
            dead = []
            for q in self.subs:
                try:
                    q.put_nowait(ev)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self.subs.remove(q)
        print(f"[{kind:8s}] ({agent}) {message}", flush=True)
        return ev

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self.subs:
            self.subs.remove(q)
