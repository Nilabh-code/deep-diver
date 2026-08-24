from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from . import BaseAgent


class Verifier(BaseAgent):
    """Confirms candidate findings safely: re-runs with clean evidence, checks
    reproducibility, never performs destructive actions."""
    name = "verifier"

    BLOCK_MARKERS = ("just a moment", "_cf_chl", "checking your browser",
                     "challenge-platform", "attention required", "access denied",
                     "rate limited", "too many requests")

    async def run(self, plan: dict) -> list[str]:
        out = []
        for f in list(self.findings.all()):
            if f.status != "candidate":
                continue
            if self.steps["used"] >= self.steps["max"]:
                break
            verdict = await self._verify(f)
            out.append(f"{f.title}: {verdict}")
        return out or ["nothing to verify"]

    async def _verify(self, f) -> str:
        try:
            self.tk.guard.check_url(f.endpoint)
        except Exception:
            f.status = "rejected"
            return "out-of-scope, rejected"
        ct = f.category
        if ct in ("sqli", "xss", "open-redirect", "path-traversal", "ssrf"):
            r = await self.tk.fetch(f.endpoint, max_bytes=40000)
            self.step(0.5)
            if not r.ok:
                f.status = "rejected"
                return "retest failed, rejected"
            ok = self._evidence_matches(ct, f, r.output, r.meta)
            if ok:
                f.status = "confirmed"
                f.repro = f.repro or f"curl -g '{f.endpoint}'"
                f.bounty_ready = f.severity in ("medium", "high", "critical")
                self.findings.items[self.findings.items.index(f)] = f
                return "confirmed"
            f.status = "rejected"
            return "no evidence on retest, rejected"
        # misconfig / auth / nuclei / takeover / secrets etc: re-check reachability
        r = await self.tk.fetch(f.endpoint, max_bytes=8000)
        self.step(0.3)
        if r.ok and r.meta.get("status", 0) in (200, 301, 302, 401, 403):
            low = (r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output).lower()[:3000]
            if any(m in low for m in self.BLOCK_MARKERS):
                f.status = "rejected"
                return "WAF challenge page, rejected"
            f.status = "confirmed"
            f.cvss = f.cvss or self._base_cvss(f.severity)
            f.bounty_ready = f.severity in ("medium", "high", "critical")
            return "confirmed"
        f.status = "rejected"
        return "not reachable, rejected"

    @staticmethod
    def _base_cvss(severity: str) -> float:
        return {"critical": 9.3, "high": 7.8, "medium": 5.4, "low": 3.1,
                "informational": 1.0}.get(severity, 1.0)

    def _evidence_matches(self, ct: str, f, body: str, meta: dict) -> bool:
        low = body.lower()
        if ct == "sqli":
            return bool(re.search(
                r"sql\s*syntax|unclosed quotation|sqlstate|ORA-\d{5}|mysql_fetch|pg_query|sqlite3\.", low))
        if ct == "xss":
            return "dv42probe" in low
        if ct == "open-redirect":
            loc = meta.get("headers", {}).get("location", "")
            return "deepdiver-redirect-test" in loc
        if ct == "path-traversal":
            return bool(re.search(r"root:.*:0:0:", body))
        if ct == "ssrf":
            return any(m in low for m in ("ami-id", "instance-id", "local-hostname"))
        return True


class Auditor(BaseAgent):
    """Dedupes, scores, writes bounty-grade reports."""
    name = "auditor"

    async def run(self, plan: dict) -> list[str]:
        confirmed = self.findings.confirmed()
        if not confirmed:
            return ["no confirmed findings to report"]
        lines = []
        for f in confirmed:
            score = self._cvss_for(f)
            if score != f.cvss:
                f.cvss = score
            lines.append(f"scored {f.title} cvss={score}")
        return lines

    def _cvss_for(self, f) -> float:
        base = {"critical": 9.3, "high": 7.8, "medium": 5.4, "low": 3.1, "informational": 1.0}
        return f.cvss or base.get(f.severity, 1.0)
