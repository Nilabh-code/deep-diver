from __future__ import annotations

import asyncio
import json
import re
import shlex
import urllib.parse
from collections import defaultdict
from collections.abc import Sequence
from urllib.parse import urlparse

from .scope import ScopeGuard, ScopeViolation


class RateGovernor:
    """Token-bucket rate limiter across the whole run; hosts all network tools."""

    def __init__(self, rps: float = 4.0):
        self.rps = max(0.25, float(rps))
        self._last = 0.0
        self._lock = asyncio.Lock()

    def set_rps(self, rps: float):
        self.rps = max(0.25, float(rps))

    async def acquire(self):
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._last + 1.0 / self.rps - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._last = now


class Toolkit:
    """All external tools + a rate-governed httpx.AsyncClient, scope-guarded."""

    def __init__(self, guard: ScopeGuard, governor: RateGovernor, workdir: str, browser: bool = True):
        self.guard = guard
        self.gov = governor
        self.workdir = workdir
        self.browser = browser
        self.timeout = 15
        self.banned_paths = {".git", "wp-login.php", "xmlrpc.php"}
        import httpx
        self.client = httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": "deep-diver/0.1 (authorized security research)"},
        )
        self._pw = None
        self._browser_ctx = None

    async def close(self):
        await self.client.aclose()
        if self._browser_ctx:
            try:
                await self._browser_ctx.close()
            except Exception:
                pass
            try:
                await self._pw.stop()
            except Exception:
                pass

    async def _pctx(self):
        if self._browser_ctx is None:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            b = await self._pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            self._browser_ctx = await b.new_context(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
                ignore_https_errors=True)
        return self._browser_ctx

    async def run_cmd(self, argv: Sequence[str], timeout: float = 180.0) -> "Result":
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
            return Result(True, out.decode("utf-8", "replace"))
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return Result(False, f"timeout after {timeout}s")
        except Exception as e:
            return Result(False, f"error: {e}")

    async def fetch(self, url: str, *, method: str = "GET", headers: dict | None = None,
                    data=None, follow: bool = True, max_bytes: int = 400_000) -> "Result":
        self.guard.check_url(url)
        await self.gov.acquire()
        try:
            r = await self.client.request(method, url, headers=headers, data=data, follow_redirects=follow)
            text = r.content[:max_bytes].decode("utf-8", "replace")
            info = f"HTTP {r.status_code} | {len(r.content)}B | final={r.url} | ct={r.headers.get('content-type', '?')}"
            return Result(True, info + "\n\n" + text, meta={"status": r.status_code, "final_url": str(r.url),
                                                            "headers": dict(r.headers), "bytes": len(r.content)})
        except Exception as e:
            return Result(False, f"request failed: {type(e).__name__}: {e}", meta={"status": 0})

    async def run_external_tool(self, name: str, args: list[str], timeout: float = 180.0) -> "Result":
        # scope-guard hosts embedded in args for the network tools
        cmd = [name, *args]
        return await self.run_cmd(cmd, timeout=timeout)

    async def subfinder(self, domain: str, passive_only: bool = True) -> "Result":
        self.guard.check_host(domain)
        args = ["-d", domain, "-silent", "-t", "30"]
        if passive_only:
            args += ["-passive"]
        r = await self.run_external_tool("subfinder", args, timeout=240)
        subs = [l.strip() for l in r.output.splitlines() if "." in l.strip()]
        subs = [s for s in subs if self.guard.is_host_allowed(s)]
        return Result(r.ok, "\n".join(subs), meta={"count": len(subs)})

    async def nuclei(self, urls: list[str], severity: str = "", tags: str = "", template_dir: str | None = None,
                     extra: list[str] | None = None) -> "Result":
        cleaned = []
        for u in urls:
            try:
                self.guard.check_url(u)
                cleaned.append(u)
            except ScopeViolation:
                continue
        if not cleaned:
            return Result(False, "no in-scope urls")
        args = ["-silent", "-rate-limit", str(int(self.gov.rps)), "-timeout", "10", "-retries", "1"]
        if severity:
            args += ["-severity", severity]
        if tags:
            args += ["-tags", tags]
        if template_dir:
            args += ["-t", template_dir]
        if extra:
            args += extra
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, dir=self.workdir) as f:
            f.write("\n".join(cleaned)); path = f.name
        args += ["-list", path]
        r = await self.run_external_tool("nuclei", args, timeout=600)
        os.unlink(path)
        findings = [l for l in r.output.splitlines() if l.strip().startswith("[")]
        return Result(r.ok, "\n".join(findings), meta={"count": len(findings)})

    async def ffuf(self, url: str, wordlist_path: str, param_pos: str = "FUZZ", mc: str = "200,201,204,301,302,307,401,403,405,500") -> "Result":
        self.guard.check_url(url.replace(param_pos, "a"))
        args = ["-u", url, "-w", wordlist_path, "-mc", mc, "-t", str(max(1, int(self.gov.rps))),
                "-s", "-o", "json", "-noninteractive", "-maxtime", "180"]
        r = await self.run_external_tool("ffuf", args, timeout=240)
        try:
            data = json.loads(r.output)
            hits = data.get("results", [])
            lines = [f"{h.get('status')} {h.get('length')}B {h.get('url', h.get('input', {}).get('FUZZ', ''))}"
                     for h in hits[:60]]
            return Result(True, "\n".join(lines), meta={"count": len(hits)})
        except json.JSONDecodeError:
            return Result(r.ok, r.output[:4000])

    async def browser_crawl(self, start_url: str, max_pages: int = 12, same_host: bool = True) -> "Result":
        self.guard.check_url(start_url)
        start_host = (urlparse(start_url).hostname or "").lower()
        ctx = await self._pctx()
        page = await ctx.new_page()
        visited: set[str] = set()
        queue = [(start_url, "")]
        endpoints = defaultdict(set)   # method -> set of url patterns
        js_urls: set[str] = set()
        forms = []
        errors = []
        console_msgs = []
        requests_seen = defaultdict(set)
        title_map = {}

        def _on_request(req):
            try:
                if req.resource_type in ("xhr", "fetch", "document"):
                    requests_seen[req.method].add(req.url.split("?")[0])
            except Exception:
                pass

        page.on("request", _on_request)
        page.on("pageerror", lambda e: errors.append(str(e)[:300]))

        pages_done = 0
        while queue and pages_done < max_pages:
            url, note = queue.pop(0)
            key = url.split("#")[0]
            if key in visited:
                continue
            u = urlparse(url)
            if same_host and (u.hostname or "").lower() != start_host:
                continue
            try:
                self.guard.check_url(url)
            except ScopeViolation:
                continue
            visited.add(key)
            pages_done += 1
            try:
                await page.goto(url, timeout=25000, wait_until="domcontentloaded")
                await page.wait_for_timeout(600)
                title = await page.title()
                title_map[key] = title
                html = await page.content()
                for m in re.finditer(r"""(?:src|href)=["']([^"']+\.js)["']""", html):
                    js_urls.add(urllib.parse.urljoin(url, m.group(1)))
                for fm in re.finditer(r"""<form[^>]*>(.*?)</form>""", html, re.S):
                    inputs = re.findall(r"""<input[^>]*name=["']([^"']+)["']""", fm.group(1))
                    forms.append({"page": key, "inputs": inputs[:12]})
                anchors = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e=>e.href).filter(h=>h.startsWith('http'))")
                for a in anchors:
                    try:
                        if (urlparse(a).hostname or "").lower() == start_host and a.split("#")[0] not in visited:
                            queue.append((a, "link"))
                    except Exception:
                        continue
            except Exception as e:
                errors.append(f"nav {url}: {e}")
        await page.close()

        try:
            self.guard.check_url(start_url)
            p2 = await ctx.new_page()
            p2.on("request", _on_request)
            await p2.goto(start_url, timeout=25000, wait_until="domcontentloaded")
            await p2.wait_for_timeout(800)
            await p2.close()
        except Exception:
            pass

        # extract endpoints from JS files
        js_ep = set()
        for ju in list(js_urls)[:15]:
            try:
                self.guard.check_url(ju)
                r = await self.fetch(ju, max_bytes=600_000)
                if r.ok:
                    body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                    for m in re.finditer(r"""["'`](/(?:api|rest|v\d|auth|admin)[A-Za-z0-9_\-./{}$:]*?)["'`]""", body):
                        js_ep.add(m.group(1))
                    for m in re.finditer(r"""https?://[A-Za-z0-9.\-]+/[A-Za-z0-9_\-./]*""", body):
                        u = m.group(0)
                        try:
                            if (urlparse(u).hostname or "").lower().endswith(start_host):
                                js_ep.add(u)
                        except Exception:
                            pass
            except ScopeViolation:
                continue
            except Exception:
                continue

        api_reqs = {m: sorted(u for u in urls if "/api" in u or "/v1" in u or "/v2" in u or "/auth" in u)
                    for m, urls in requests_seen.items()}
        summary = {
            "pages": pages_done, "visited": sorted(visited)[:40], "titles": {k: v for k, v in list(title_map.items())[:30]},
            "js_files": sorted(js_urls)[:20], "js_endpoints": sorted(js_ep)[:40],
            "forms": forms[:20], "api_requests": {m: u[:20] for m, u in api_reqs.items()},
            "page_errors": errors[:10],
        }
        return Result(True, json.dumps(summary, indent=1)[:12000], meta=summary)

    async def browser_probe(self, url: str, action: str = "auto", params: dict | None = None) -> "Result":
        """Open a URL in-browser, capture console errors, network, and optionally
        fill forms to trigger client-side bugs."""
        self.guard.check_url(url)
        ctx = await self._pctx()
        page = await ctx.new_page()
        console, errors, reqs = [], [], []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text[:200]}") if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: errors.append(str(e)[:300]))
        page.on("request", lambda r: reqs.append(f"{r.method} {r.url[:200]}") if r.resource_type in ("xhr", "fetch", "websocket") else None)
        try:
            resp = await page.goto(url, timeout=25000, wait_until="networkidle")
            status = resp.status if resp else 0
        except Exception as e:
            return Result(False, f"navigation failed: {e}")
        title = await page.title()
        out = {
            "status": status, "title": title, "console": console[:15],
            "page_errors": errors[:10], "api_requests": reqs[:20],
        }
        if action in ("auto", "forms") :
            forms_found = 0
            try:
                forms = await page.query_selector_all("form")
                for form in forms[:3]:
                    inputs = await form.query_selector_all("input,textarea,select")
                    for inp in inputs[:8]:
                        try:
                            name = await inp.get_attribute("name") or await inp.get_attribute("id") or ""
                            itype = (await inp.get_attribute("type") or "text").lower()
                            if itype in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                                continue
                            val = ""
                            if itype == "email":
                                val = params.get(name, "probe@test.local") if params else "probe@test.local"
                            elif itype in ("number", "tel"):
                                val = params.get(name, "1234") if params else "1234"
                            elif "name" in name.lower() or "user" in name.lower():
                                val = params.get(name, "probeuser") if params else "probeuser"
                            elif "search" in name.lower() or "q" in name.lower():
                                val = params.get(name, "probe") if params else "probe"
                            elif itype == "password":
                                val = params.get(name, "Probe#1234") if params else "Probe#1234"
                            else:
                                val = params.get(name, "probe") if params else "probe"
                            await inp.fill(val)
                        except Exception:
                            continue
                    forms_found += 1
                    try:
                        btn = await form.query_selector("[type=submit],button")
                        if btn and forms_found == 1:
                            await btn.click(timeout=5000)
                            await page.wait_for_timeout(1200)
                    except Exception:
                        pass
            except Exception:
                pass
            out["forms_filled"] = forms_found
        await page.close()
        return Result(True, json.dumps(out, indent=1)[:8000], meta=out)


class Result:
    __slots__ = ("ok", "output", "meta")

    def __init__(self, ok: bool, output: str, meta: dict | None = None):
        self.ok = ok
        self.output = output
        self.meta = meta or {}

    def truncate(self, n: int = 6000) -> str:
        return self.output[:n] + ("\n…[truncated]" if len(self.output) > n else "")


async def guard_wrap(guard: ScopeGuard, coro_name: str, *args, **kwargs):
    """Central scope assertion for host/url-ish args — defense in depth on top of
    the per-tool checks."""
    for a in list(args) + list(kwargs.values()):
        if isinstance(a, str) and ("://" in a):
            guard.check_url(a)
    return (coro_name, args, kwargs)
