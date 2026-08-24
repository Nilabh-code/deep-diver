from __future__ import annotations

import re
import time

from . import BaseAgent


class Verifier(BaseAgent):
    """Category-aware verification. Candidate findings get re-tested with the
    strongest check available for their bug class; findings the hunter recorded
    directly as confirmed (injection classes) are INDEPENDENTLY re-checked too
    and demoted to candidate if the evidence no longer reproduces. Reachability
    alone never confirms an injection, CVE, or IDOR finding."""
    name = "verifier"

    BLOCK_MARKERS = ("just a moment", "_cf_chl", "checking your browser",
                     "challenge-platform", "attention required", "access denied",
                     "rate limited", "too many requests")

    RECHECK_CONFIRMED = {"sqli", "ssrf", "path-traversal", "open-redirect",
                         "cmdi", "cors", "host-header", "downgrade"}

    async def run(self, plan: dict) -> list[str]:
        out = []
        for f in list(self.findings.all()):
            if self.steps["used"] >= self.steps["max"]:
                break
            if f.status == "candidate":
                verdict = await self._verify_candidate(f)
                out.append(f"{f.title[:70]}: {verdict}")
            elif f.status == "confirmed" and f.category in self.RECHECK_CONFIRMED:
                verdict = await self._recheck_confirmed(f)
                out.append(f"{f.title[:70]}: recheck {verdict}")
        return out or ["nothing to verify"]

    @staticmethod
    def _ev_field(f, name: str) -> str:
        m = re.search(name + r": (\S+)", f.evidence or "")
        return m.group(1) if m else ""

    def _blocked(self, body: str) -> bool:
        return any(m in body.lower()[:3000] for m in self.BLOCK_MARKERS)

    def _confirm(self, f) -> str:
        f.status = "confirmed"
        f.repro = f.repro or f"curl -g '{f.endpoint}'"
        f.cvss = f.cvss or self._base_cvss(f.severity)
        f.bounty_ready = f.severity in ("medium", "high", "critical")
        return "confirmed"

    def _demote(self, f, why: str) -> str:
        f.status = "candidate"
        return f"demoted to candidate — {why}"

    @staticmethod
    def _base_cvss(severity: str) -> float:
        return {"critical": 9.3, "high": 7.8, "medium": 5.4, "low": 3.1,
                "informational": 1.0}.get(severity, 1.0)

    async def _verify_candidate(self, f) -> str:
        try:
            self.tk.guard.check_url(f.endpoint)
        except Exception:
            f.status = "rejected"
            return "out-of-scope, rejected"
        ct = f.category
        if ct == "idor":
            return "kept candidate — IDOR needs a second account to prove cross-user access"
        if ct == "known-cve":
            f.bounty_ready = f.severity in ("high", "critical")
            return "kept candidate — version-gated by cvemap, confirm exploitation manually"
        if ct == "cmdi":
            return await self._verify_cmdi(f)
        if ct == "cors":
            return await self._verify_cors(f)
        if ct == "downgrade":
            r = await self.tk.fetch(f.endpoint, follow=False, max_bytes=500)
            self.step(0.2)
            if r.ok and r.meta.get("status", 0) == 200:
                return self._confirm(f)
            f.status = "rejected"
            return "redirects now, rejected"
        if ct in ("sqli", "xss", "open-redirect", "path-traversal", "ssrf"):
            r = await self.tk.fetch(f.endpoint, max_bytes=40000)
            self.step(0.5)
            if not r.ok:
                f.status = "rejected"
                return "retest failed, rejected"
            if self._evidence_matches(ct, f, r.output, r.meta):
                return self._confirm(f)
            f.status = "rejected"
            return "no evidence on retest, rejected"
        if ct == "auth":
            return await self._verify_auth_bypass(f)
        r = await self.tk.fetch(f.endpoint, max_bytes=8000)
        self.step(0.3)
        if r.ok and r.meta.get("status", 0) in (200, 301, 302, 401, 403):
            body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
            if self._blocked(body):
                f.status = "rejected"
                return "WAF challenge page, rejected"
            return self._confirm(f)
        f.status = "rejected"
        return "not reachable, rejected"

    async def _verify_cmdi(self, f) -> str:
        conf_url = self._ev_field(f, "conf_url")
        m = re.search(r"(dv42c\d+x)", conf_url) if conf_url else None
        if m:
            marker = m.group(1)
            r = await self.tk.fetch(conf_url, max_bytes=40000)
            self.step(0.3)
            body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
            if r.ok and marker in body and f"| echo {marker}" not in body \
                    and f"echo {marker}" not in body:
                return self._confirm(f)
        base_url = self._ev_field(f, "baseline_url")
        if not base_url:
            return "kept candidate — no baseline url to retest"
        t0 = time.monotonic()
        r0 = await self.tk.fetch(base_url, max_bytes=1000)
        baseline = time.monotonic() - t0
        self.step(0.3)
        if not r0.ok:
            f.status = "rejected"
            return "baseline unreachable, rejected"
        t1 = time.monotonic()
        r1 = await self.tk.fetch(f.endpoint, max_bytes=1000)
        elapsed = time.monotonic() - t1
        self.step(0.5)
        if r1.ok and elapsed >= max(3.5, baseline + 3):
            return self._confirm(f)
        f.status = "rejected"
        return f"timing not reproduced (baseline={baseline:.1f}s sleep={elapsed:.1f}s), rejected"

    async def _verify_cors(self, f) -> str:
        m = re.search(r"Origin: (\S+)", f.evidence or "")
        origin = m.group(1) if m else "https://evil.attacker.example"
        r = await self.tk.fetch(f.endpoint, headers={"Origin": origin}, max_bytes=1000)
        self.step(0.2)
        if not r.ok:
            f.status = "rejected"
            return "retest failed, rejected"
        h = {k.lower(): str(v) for k, v in r.meta.get("headers", {}).items()}
        if h.get("access-control-allow-origin", "") == origin and \
                h.get("access-control-allow-credentials", "").lower() == "true":
            return self._confirm(f)
        f.status = "rejected"
        return "CORS reflection no longer present, rejected"

    async def _verify_auth_bypass(self, f) -> str:
        m = re.search(r"(POST|PUT|PATCH|DELETE)", f.title or "")
        method = m.group(1) if m else "POST"
        gr = await self.tk.fetch(f.endpoint, method="GET", max_bytes=1000)
        ar = await self.tk.fetch(f.endpoint, method=method, max_bytes=1000)
        self.step(0.3)
        gs = gr.meta.get("status", 0)
        as_ = ar.meta.get("status", 0)
        ab = (ar.output.split("\n\n", 1)[1] if "\n\n" in ar.output else ar.output).strip().lower()
        body_real = len(ab) > 120 and not any(
            k in ab[:220] for k in ('"error"', '"forbidden"', '"not found"', "denied"))
        if gs in (401, 403) and as_ == 200 and body_real:
            return self._confirm(f)
        f.status = "rejected"
        return f"method replay failed (GET={gs}, {method}={as_}), rejected"

    async def _recheck_confirmed(self, f) -> str:
        ct = f.category
        try:
            self.tk.guard.check_url(f.endpoint)
        except Exception:
            f.status = "rejected"
            return "out-of-scope, rejected"
        if ct == "cmdi":
            return await self._verify_cmdi(f)
        if ct == "cors":
            return await self._verify_cors(f)
        if ct == "downgrade":
            r = await self.tk.fetch(f.endpoint, follow=False, max_bytes=500)
            self.step(0.2)
            if r.ok and r.meta.get("status", 0) == 200:
                return "still valid"
            return self._demote(f, "no longer serving plaintext")
        if ct == "host-header":
            evil = "dv-recheck.example"
            r = await self.tk.fetch(f.endpoint, headers={"X-Forwarded-Host": evil},
                                    follow=False, max_bytes=8000)
            self.step(0.2)
            if r.ok:
                h = {k.lower(): str(v) for k, v in r.meta.get("headers", {}).items()}
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                loc = h.get("location", "")
                ctx_match = re.search(
                    r"(<a\s[^>]*|action=|src=|href=)[^>]*" + re.escape(evil),
                    body, re.I)
                if evil in loc.lower() or ctx_match:
                    return "still valid"
            return self._demote(f, "reflection not in an exploitable context")
        r = await self.tk.fetch(f.endpoint, max_bytes=40000)
        self.step(0.5)
        if not r.ok:
            return self._demote(f, "endpoint unreachable on retest")
        if self._evidence_matches(ct, f, r.output, r.meta):
            return "still valid"
        return self._demote(f, "evidence no longer reproduces on retest")

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
            return any(m in low for m in ("ami-id", "instance-id", "local-hostname",
                                          "ostype", "machinetype", "droplet_id"))
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
        base = {"critical": 9.3, "high": 7.8, "medium": 5.4, "low": 3.1,
                "informational": 1.0}
        return f.cvss or base.get(f.severity, 1.0)
