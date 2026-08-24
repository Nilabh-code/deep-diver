from __future__ import annotations

import json
import re
import urllib.parse
from urllib.parse import urlparse

from . import BaseAgent


class ApiScanner(BaseAgent):
    """Faces exposed on Next.js/SPA stacks: extracts real API routes directly from
    the app bundle, probes GraphQL introspection, brute-forces common API paths."""
    name = "apiscan"

    async def run(self, plan: dict) -> list[str]:
        hosts = plan.get("hosts") or sorted(self.surf.hosts)[:3]
        out = []
        for host in hosts:
            try:
                self.tk.guard.check_url(host if "://" in host else f"https://{host}")
            except Exception:
                await self.say(f"skipping out-of-scope api target: {host}", kind="error")
                continue
            await self.say(f"api mapping {host}")
            n1 = await self._nextjs_routes(host)
            n2 = await self._js_route_harvest(host)
            n3 = await self._graphql(host)
            n4 = await self._api_brute(host)
            n5 = await self._wellknown(host)
            n6 = await self._ai_endpoints(host)
            out.append(f"{urlparse(host).netloc}: +{n1} nextjs, +{n2} js-harvest, "
                       f"graphql={n3}, +{n4} bruteforce, +{n5} wellknown, +{n6} ai")
        return out or ["no hosts"]

    async def _nextjs_routes(self, host: str) -> int:
        found = 0
        r = await self.tk.fetch(host, max_bytes=400000)
        if not r.ok:
            return 0
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        bm = re.search(r'src="(/_next/static/[A-Za-z0-9_\-/.]+/_buildManifest[^"\']*)"', body) \
            or re.search(r'src="(/_next/static/[^"\']*/_buildManifest.js)"', body)
        if bm:
            url = urllib.parse.urljoin(host, bm.group(1))
            r2 = await self.tk.fetch(url, max_bytes=500000)
            if r2.ok:
                jb = r2.output.split("\n\n", 1)[1] if "\n\n" in r2.output else r2.output
                for m in re.finditer(r'"(/[^"]*?)":\[', jb):
                    path = m.group(1)
                    if path == "/404" or "/_next/" in path:
                        continue
                    full = host.rstrip("/") + ("" if path == "/" else path)
                    if full not in self.surf.urls:
                        self.surf.urls.add(full)
                        found += 1
        return found

    async def _js_route_harvest(self, host: str) -> int:
        base = urlparse(host)
        base_url = f"{base.scheme}://{base.netloc}"
        js_seen: set[str] = set()
        for u in list(self.surf.urls):
            if urlparse(u).netloc == base.netloc and u.rstrip().endswith(".js"):
                js_seen.add(u)
        index = await self.tk.fetch(host, max_bytes=400000)
        if index.ok:
            body = index.output.split("\n\n", 1)[1] if "\n\n" in index.output else index.output
            for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js)["\']', body):
                u = urllib.parse.urljoin(host, m.group(1))
                try:
                    self.tk.guard.check_url(u)
                    js_seen.add(u)
                except Exception:
                    pass
        found = 0
        route_re = re.compile(r'["\'](/(?:api|auth|admin|internal|graphql|webhooks?|v\d+|static/api)[A-Za-z0-9_\-./]*)["\'\\]')
        fetch_re = re.compile(r'(?:fetch|axios|\.get|\.post|\.put|\.patch|\.delete)\(\s*[`"\'](/[^`"\']{2,120})[`"\']')
        vercel_re = re.compile(r'["\'](/api/[A-Za-z0-9_\-$\[\]/.]+)["\']')
        for u in sorted(js_seen)[:25]:
            r = await self.tk.fetch(u, max_bytes=900000)
            self.step(0.2)
            if not r.ok:
                continue
            body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
            hits = set()
            for rx in (route_re, fetch_re, vercel_re):
                for m in rx.finditer(body):
                    p = m.group(1).split('"')[0].split("`")[0].split("?")[0]
                    if re.fullmatch(r"/[A-Za-z0-9_\-./$]*", p) and len(p) < 100:
                        hits.add(p)
            for p in hits:
                full = base_url + p
                try:
                    self.tk.guard.check_url(full)
                except Exception:
                    continue
                if full not in self.surf.urls and "/_next/" not in p and ".js" not in p:
                    self.surf.urls.add(full)
                    self.surf.js_endpoints.add(full)
                    found += 1
        await self.say(f"js harvest: +{found} api routes from {len(js_seen)} chunks")
        return found

    async def _graphql(self, host: str) -> int:
        introspect = ('{"query":"{ __schema { queryType { name } types { name } } }"}')
        found = 0
        for path in ("/graphql", "/api/graphql", "/v1/graphql"):
            url = host.rstrip("/") + path
            r = await self.tk.fetch(url, method="POST",
                                    headers={"Content-Type": "application/json"},
                                    data=introspect, max_bytes=30000)
            self.step(0.2)
            if r.ok and ('"__schema"' in r.output or
                         ('"queryType"' in r.output and '"types"' in r.output)):
                found += 1
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                types = re.findall(r'"name":"([A-Za-z0-9_]+)"', body)[:20]
                await self.record(
                    title=f"GraphQL introspection enabled at {path}",
                    severity="medium", category="misconfig", endpoint=url,
                    evidence=body[:2000],
                    repro=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{introspect}'",
                    impact="Full schema disclosure — enumerates sensitive operations/types",
                    cvss=5.3, status="confirmed", bounty_ready=True)
        return found

    async def _api_brute(self, host: str) -> int:
        import os
        wl = "/home/nil/projects/deep-diver/wordlists/api-endpoints.txt"
        if not os.path.exists(wl):
            return 0
        u = host.rstrip("/") + "/FUZZ"
        r = await self.tk.ffuf(u, wl, mc="200,201,204,301,302,307,401,403,405")
        self.step()
        found = 0
        for line in r.output.splitlines():
            m = re.match(r"(\d+)\s+(\d+)B\s+(.*)", line)
            if not m:
                continue
            status, size, url = m.groups()
            url = url.strip()
            if not url or "/api" not in url.lower():
                continue
            if url not in self.surf.urls:
                self.surf.urls.add(url)
                self.surf.js_endpoints.add(url)
                found += 1
                if status in ("200", "401", "403"):
                    await self.record(title=f"API endpoint {urlparse(url).path} ({status})",
                                      severity="informational", category="recon",
                                      endpoint=url, evidence=f"HTTP {status} {size}B",
                                      status="candidate")
        return found

    async def _wellknown(self, host: str) -> int:
        found = 0
        for path in ("/.well-known/openid-configuration", "/.well-known/security.txt",
                     "/.well-known/ai-plugin.json", "/.well-known/oauth-authorization-server",
                     "/sitemap.xml", "/openapi.json", "/api-docs", "/api/openapi.json",
                     "/api/docs", "/swagger/v1/swagger.json", "/_next/data/"):
            url = host.rstrip("/") + path
            r = await self.tk.fetch(url, max_bytes=8000)
            self.step(0.1)
            if r.ok and r.meta.get("status") == 200 and len(r.output) > 200:
                ct = r.meta.get("headers", {}).get("content-type", "")
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                if "<html" in body.lower()[:1500] and not url.endswith((".html",)):
                    continue
                found += 1
                self.surf.urls.add(url)
                if any(k in url for k in ("openapi", "swagger", "security", "ai-plugin")):
                    await self.record(title=f"disclosure file {urlparse(url).path}",
                                      severity="low", category="recon", endpoint=url,
                                      evidence=body[:800], status="candidate")
        return found

    async def _ai_endpoints(self, host: str) -> int:
        """garak-style shadow-AI discovery: exposed LLM/model/agent endpoints."""
        found = 0
        probes = [
            ("/v1/models", "openai-compatible model list"),
            ("/api/tags", "ollama model list"),
            ("/v1/chat/completions", "llm chat endpoint"),
            ("/api/generate", "ollama generate"),
            ("/gradio", "gradio app"),
            ("/api/openai", "openai proxy"),
            ("/mcp", "model context protocol"),
            ("/llm", "generic llm route"),
        ]
        for path, desc in probes:
            url = f"{host.rstrip('/')}{path}"
            r = await self.tk.fetch(url, max_bytes=8000)
            self.step(0.1)
            status = r.meta.get("status", 0)
            if status == 200:
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                low = body.lower()[:3000]
                if "<html" in low:
                    continue
                hit = any(k in low for k in ('"data"', '"models"', '"id"', "llama",
                                             '"name"', "model")) or path == "/api/tags"
                if hit:
                    found += 1
                    self.surf.urls.add(url)
                    await self.record(title=f"exposed AI endpoint: {desc} at {path}",
                                      severity="medium", category="ai-exposure",
                                      endpoint=url, evidence=body[:1000],
                                      impact="Shadow AI surface — prompt injection / data leak / cost abuse vector",
                                      cvss=5.3, status="confirmed")
        return found
