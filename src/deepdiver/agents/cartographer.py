from __future__ import annotations

import json
import re
import urllib.parse
from urllib.parse import urlparse

from . import BaseAgent


class Cartographer(BaseAgent):
    name = "cartographer"

    async def run(self, plan: dict) -> list[str]:
        """Crawl live hosts: katana for link discovery, Playwright browser crawl for
        JS-heavy pages, builds URL/param/endpoint/form map."""
        hosts = plan.get("hosts") or sorted(self.surf.hosts)[:5]
        out = []
        for host in hosts[: plan.get("max_hosts", 5)]:
            if self.steps["used"] >= self.steps["max"]:
                break
            await self.say(f"crawling {host}")
            await self._katana(host)
            if self.tk.browser:
                await self._browser_crawl(host)
            await self._extract_params()
            out.append(f"mapped {host}")
        return out or ["no hosts to crawl"]

    async def _katana(self, host: str):
        r = await self.tk.run_external_tool(
            "katana", ["-u", host, "-silent", "-jc", "-kf", "all", "-d", "2",
                       "-aff", "-ct", "8", "-fs", "fqdn,rdn", "-timeout", "15",
                       "-rl", str(max(1, int(self.tk.gov.rps)))],
            timeout=300)
        self.step()
        new = 0
        for line in r.output.splitlines():
            line = line.strip()
            if not line.startswith("http"):
                continue
            try:
                self.tk.guard.check_url(line)
            except Exception:
                continue
            if line not in self.surf.urls:
                self.surf.urls.add(line)
                new += 1
        await self.say(f"katana: +{new} urls (total {len(self.surf.urls)})")

    async def _browser_crawl(self, host: str):
        key = f"bcrawl:{host}"
        if key in self.surf.explored_actions:
            return
        self.surf.explored_actions.add(key)
        r = await self.tk.browser_crawl(host, max_pages=10)
        self.step()
        if not r.ok:
            await self.say(f"browser crawl failed on {host}: {r.output[:120]}")
            return
        meta = r.meta or {}
        for u in meta.get("visited", []):
            self.surf.urls.add(u)
        for ep in meta.get("js_endpoints", []):
            self.surf.js_endpoints.add(ep)
        for form in meta.get("forms", []):
            if form not in self.surf.forms:
                self.surf.forms.append(form)
        for u, t in meta.get("titles", {}).items():
            self.surf.titles.setdefault(u, t)
        for m, urls in meta.get("api_requests", {}).items():
            for u in urls:
                self.surf.urls.add(u)
        await self.say(
            f"browser crawl: {meta.get('pages', 0)} pages, "
            f"+{len(meta.get('js_endpoints', []))} js endpoints, {len(meta.get('forms', []))} forms")

    async def _extract_params(self):
        for u in list(self.surf.urls):
            q = urlparse(u).query
            if not q:
                continue
            base = u.split("?")[0]
            for pair in q.split("&"):
                if "=" in pair:
                    name = pair.split("=")[0]
                    if re.fullmatch(r"[A-Za-z0-9_\-\[\]]+", name):
                        self.surf.params[base].add(name)

    async def interesting_endpoints(self) -> list[str]:
        """Prioritize URLs likely to accept input: contain params, api paths, forms."""
        scored = []
        for u in self.surf.urls:
            score = 0
            lu = u.lower()
            if urlparse(u).query:
                score += 3
            if any(k in lu for k in ("/api/", "/search", "/login", "/register", "/upload",
                                     "/admin", "/graphql", "?id=", "?url=", "?redirect")):
                score += 2
            scored.append((score, u))
        scored.sort(reverse=True)
        return [u for _, u in scored[:80]]
