from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict


SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass
class Finding:
    title: str
    severity: str                # informational|low|medium|high|critical
    category: str                # e.g. sqli, xss, idor, takeover, secrets, misconfig, auth
    endpoint: str
    agent: str
    status: str = "candidate"    # candidate|confirmed|rejected|duplicate
    evidence: str = ""
    repro: str = ""
    impact: str = ""
    cvss: float = 0.0
    bounty_ready: bool = False
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class FindingStore:
    def __init__(self):
        self.items: list[Finding] = []

    def add(self, f: Finding) -> Finding:
        fp = (f.category.lower(), f.endpoint.lower(), f.title.lower())
        for existing in self.items:
            ep = (existing.category.lower(), existing.endpoint.lower(), existing.title.lower())
            if ep == fp:
                existing.status = existing.status if existing.status == "confirmed" else f.status
                f.status = "duplicate"
                self.items.append(f)
                return f
        self.items.append(f)
        return f

    def confirmed(self) -> list[Finding]:
        return [f for f in self.items if f.status == "confirmed"]

    def all(self) -> list[Finding]:
        return list(self.items)
