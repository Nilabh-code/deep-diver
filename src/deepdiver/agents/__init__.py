from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from urllib.parse import urlparse

from ..events import EventBus
from ..models import Finding, FindingStore
from ..state import AttackSurface
from ..tools import Toolkit


class BaseAgent:
    name = "base"

    def __init__(self, tk: Toolkit, surface: AttackSurface, bus: EventBus, findings: FindingStore, steps: dict):
        self.tk = tk
        self.surf = surface
        self.bus = bus
        self.findings = findings
        self.steps = steps      # shared counters: {"used": int, "max": int}

    async def say(self, msg: str, kind: str = "agent", data: dict | None = None):
        await self.bus.publish(kind, self.name, msg, data)

    def step(self, n: int = 1):
        self.steps["used"] += n

    async def record(self, title: str, severity: str, category: str, endpoint: str,
                     evidence: str, repro: str = "", impact: str = "", cvss: float = 0.0,
                     status: str = "candidate", bounty_ready: bool = False):
        f = Finding(title=title, severity=severity, category=category, endpoint=endpoint,
                    agent=self.name, evidence=evidence[:4000], repro=repro[:2000],
                    impact=impact, cvss=cvss, status=status, bounty_ready=bounty_ready)
        self.findings.add(f)
        await self.bus.publish("finding", self.name,
                               f"[{status}] {severity.upper()} {category}: {title} @ {endpoint}",
                               f.to_dict())
        return f
