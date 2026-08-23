from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class AttackSurface:
    root_target: str = ""
    hosts: set[str] = field(default_factory=set)          # live hosts (scheme://host)
    urls: set[str] = field(default_factory=set)           # discovered URLs
    params: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # url-ish key -> param names
    js_endpoints: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    tech: dict[str, str] = field(default_factory=dict)    # host -> tech fingerprint
    titles: dict[str, str] = field(default_factory=dict)
    ports: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    notes: list[str] = field(default_factory=list)
    explored_actions: set[str] = field(default_factory=set)

    def add_note(self, note: str):
        self.notes.append(f"[{time.strftime('%H:%M:%S')}] {note}")

    def summary(self, max_items: int = 60) -> str:
        def lst(s, n=max_items):
            items = sorted(s)[:n]
            more = len(s) - len(items)
            return "\n".join(items) + (f"\n… +{more} more" if more > 0 else "")
        parts = [f"target: {self.root_target}"]
        if self.hosts:
            parts.append(f"live hosts ({len(self.hosts)}):\n{lst(self.hosts)}")
        if self.ports:
            plines = "\n".join(f"  {h}: {sorted(p)}" for h, p in sorted(self.ports.items())[:max_items])
            parts.append(f"open ports:\n{plines}")
        if self.tech:
            tlines = "\n".join(f"  {h}: {t}" for h, t in sorted(self.tech.items())[:max_items])
            parts.append(f"tech:\n{tlines}")
        if self.titles:
            tls = "\n".join(f"  {u}: {t[:60]}" for u, t in sorted(self.titles.items())[:40])
            parts.append(f"page titles:\n{tls}")
        if self.urls:
            parts.append(f"discovered urls ({len(self.urls)}):\n{lst(self.urls)}")
        if self.js_endpoints:
            parts.append(f"js/api endpoints ({len(self.js_endpoints)}):\n{lst(self.js_endpoints)}")
        if self.forms:
            fl = "\n".join(f"  {f['page']} inputs={f.get('inputs')}" for f in self.forms[:25])
            parts.append(f"forms:\n{fl}")
        if self.notes:
            parts.append("notes:\n" + "\n".join(self.notes[-15:]))
        return "\n\n".join(parts)

    def url_candidates(self) -> list[str]:
        return sorted(self.urls)[:500]
