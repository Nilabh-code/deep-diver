from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from urllib.parse import urlparse, parse_qsl, urlencode

from . import BaseAgent

# Safe-by-design payload policy: detection markers only, never destructive.
PROBE_ID = "dv42probe"

SQLI_PAYLOADS = [
    f"'{PROBE_ID}",
    f"\"{PROBE_ID}",
    f"1'{PROBE_ID}",
    f"1) or '{PROBE_ID}'='",
]
SQLI_ERRORS = re.compile(
    r"sql\s*syntax|mysql_fetch|unclosed quotation|quoted string not properly terminated|"
    r"microsoft ole db|pgsql|pg_query|sqlite3\.|syntax error at or near|ORA-\d{5}|"
    r"Warning: mysqli|Unclosed quotation mark|JDBC|SQLSTATE", re.I)

XSS_PAYLOADS = [
    f'<svg onload={PROBE_ID}()>',
    f'"><img src=x onerror={PROBE_ID}()>',
    f"javascript:{PROBE_ID}()",
]

REDIRECT_PAYLOADS = [
    "https://deepdiver-redirect-test.example.com/",
    "//deepdiver-redirect-test.example.com/",
]

SSRF_MARKERS = ("ami-id", "instance-id", "ami-launch-index", "local-hostname",
                "compute/metadata", '"project":', " VIA HTTP/1.1")

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/config.json", "/backup.sql", "/db.sqlite3", "/.svn/entries", "/.DS_Store",
    "/server-status", "/actuator/health", "/actuator/env", "/api/swagger.json",
    "/swagger-ui.html", "/graphql", "/debug/pprof/", "/trace", "/console/",
    "/phpmyadmin/", "/admin/", "/wp-json/wp/v2/users", "/.aws/credentials",
    "/application.properties", "/configuration.php", "/web.config", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/.npmrc", "/.pypirc", "/id_rsa", "/.ssh/id_rsa",
]


class Hunter(BaseAgent):
    name = "hunter"

    async def run(self, plan: dict) -> list[str]:
        actions = plan.get("actions", [])
        if not actions and plan.get("action"):
            actions = [{"action": plan["action"], "args": plan.get("args", {})}]
        if isinstance(actions, dict):
            actions = [actions]
        out = []
        for act in actions:
            if self.steps["used"] >= self.steps["max"]:
                break
            name = act.get("action")
            args = act.get("args", {})
            fn = getattr(self, f"a_{name}", None)
            if not fn:
                out.append(f"unknown action {name}")
                continue
            try:
                res = await fn(**args)
                out.append(f"{name}: {res}")
            except Exception as e:
                out.append(f"{name} error: {type(e).__name__}: {e}")
                await self.say(f"{name} raised {type(e).__name__}: {e}", kind="error")
        return out

    def _urls_with_params(self):
        return [u for u in self.surf.urls if urlparse(u).query]

    async def a_nuclei_scan(self, tags: str = "", severity: str = "", urls: list[str] | None = None) -> str:
        targets = urls or sorted(self.surf.hosts)
        if not targets:
            return "no targets"
        r = await self.tk.nuclei(targets, severity=severity, tags=tags,
                                 template_dir="/home/nil/nuclei-templates")
        self.step()
        count = 0
        for line in r.output.splitlines():
            m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
            if not m:
                continue
            template, sev, rest = m.group(1), m.group(2).lower(), m.group(3)
            sev_map = {"info": "informational", "low": "low", "medium": "medium",
                       "high": "high", "critical": "critical"}
            sev = sev_map.get(sev, "informational")
            endpoint = rest.split("[")[0].strip() or rest.strip()
            await self.record(title=f"nuclei:{template}", severity=sev, category="nuclei",
                              endpoint=endpoint, evidence=line)
            count += 1
        return f"{count} nuclei hits"

    async def a_takeover_check(self) -> str:
        hosts = [h.replace("https://", "").replace("http://", "") for h in self.surf.hosts]
        subs = hosts
        r = await self.tk.nuclei([f"http://{s}" for s in subs[:30]], tags="takeover",
                                 template_dir="/home/nil/nuclei-templates")
        self.step()
        hits = [l for l in r.output.splitlines() if l.strip()]
        for h in hits[:10]:
            await self.record(title="possible subdomain takeover", severity="high", category="takeover",
                              endpoint=h, evidence=h)
        return f"{len(hits)} takeover candidates"

    async def a_sensitive_files(self) -> str:
        hits = 0
        for host in sorted(self.surf.hosts)[:10]:
            base = host.rstrip("/")
            home_sig = await self._home_fingerprint(base)
            for path in SENSITIVE_PATHS:
                url = base + path
                r = await self.tk.fetch(url, max_bytes=8000)
                self.step(0.1)
                if not r.ok:
                    continue
                status = r.meta.get("status", 0)
                ct = r.meta.get("headers", {}).get("content-type", "")
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                if status != 200:
                    continue
                if self._looks_like_spafallback(url, ct, body, home_sig):
                    continue
                if self._interesting_sensitive(path, body, len(body)):
                    hits += 1
                    await self.record(
                        title=f"sensitive file exposed: {path}",
                        severity=self._sensitive_sev(path),
                        category="misconfig", endpoint=url,
                        evidence=f"HTTP {status} {ct}\n{body[:1500]}")
        return f"{hits} sensitive file hits"

    async def _home_fingerprint(self, base: str) -> set[str]:
        r = await self.tk.fetch(base, max_bytes=8000)
        if not r.ok:
            return set()
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        return set(re.findall(r'<title>([^<]{4,80})</title>', body)) or {"__home__"}

    def _looks_like_spafallback(self, url: str, ct: str, body: str, home_sig: set[str]) -> bool:
        low = body[:4000].lower()
        if "html" in ct and not url.lower().endswith((".html",)):
            titles = set(re.findall(r"<title>([^<]{4,80})</title>", low))
            if home_sig and titles and titles == home_sig:
                return True
            if "<!doctype html" in low or ("<html" in low and "password" not in low
                                             and "[core]" not in low):
                return True
        return False

    def _interesting_sensitive(self, path: str, body: str, length: int) -> bool:
        low = body.lower()
        if length < 12:
            return False
        markers = {
            "/.git/config": ("[core]", "[remote"),
            "/.env": ("=",),
            "/robots.txt": ("disallow", "allow:", "user-agent"),
            "/server-status": ("apache server status", "uptime"),
            "/actuator/health": ('"status"',),
            "/actuator/env": ('"property"', '"key"'),
            "/api/swagger.json": ('"swagger"', '"openapi"', '"paths"'),
            "/graphql": ('"data"', '"errors"', "query"),
            "/wp-json/wp/v2/users": ('"id"', '"slug"'),
            "/crossdomain.xml": ("allow-access-from",),
        }
        for p, ms in markers.items():
            if path.startswith(p):
                if "/.env" == p and "<html" in low:
                    return False
                return any(m in low for m in ms)
        if path in ("/.aws/credentials", "/id_rsa", "/.ssh/id_rsa", "/.npmrc", "/.pypirc"):
            return "aws_access" in low or "private key" in low or "_auth" in low
        if path.endswith((".sql", ".sqlite3")):
            return length > 100 and "<html" not in low
        if "<html" in low and not any(k in low for k in ("password = ", "secret_key", "db_password", "apikey=")):
            return False
        return any(m in low for m in ("password", "secret", "token", "dbname", "private key"))

    def _sensitive_sev(self, path: str) -> str:
        if path in ("/.git/config", "/.env", "/.aws/credentials", "/id_rsa", "/.ssh/id_rsa",
                    "/.npmrc", "/.pypirc", "/backup.sql", "/db.sqlite3"):
            return "high"
        if path in ("/server-status", "/actuator/env", "/trace", "/debug/pprof/", "/console/",
                    "/phpmyadmin/", "/admin/", "/application.properties", "/configuration.php"):
            return "medium"
        return "low"

    async def _prepare_param_targets(self, max_urls: int = 40):
        """Yield (base_url, params_dict) for URLs with query params, in-scope only."""
        targets = []
        seen = set()
        for u in self._urls_with_params():
            p = urlparse(u)
            q = parse_qsl(p.query, keep_blank_values=True)
            key = (p.netloc, p.path, tuple(sorted(k for k, _ in q)))
            if key in seen:
                continue
            seen.add(key)
            targets.append((u, dict(q)))
            if len(targets) >= max_urls:
                break
        return targets

    async def a_test_sqli(self, max_urls: int = 30) -> str:
        targets = await self._prepare_param_targets(max_urls)
        confirmed, candidates = 0, 0
        for url, params in targets:
            p = urlparse(url)
            for pname in list(params.keys())[:4]:
                for payload in SQLI_PAYLOADS:
                    q = dict(params)
                    q[pname] = payload
                    test_url = f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"
                    r = await self.tk.fetch(test_url, max_bytes=50000)
                    self.step(0.25)
                    if r.ok and SQLI_ERRORS.search(r.output):
                        confirmed += 1
                        await self.record(
                            title=f"SQL injection in parameter '{pname}'",
                            severity="critical" if "error" in str(SQLI_ERRORS.pattern) else "high",
                            category="sqli", endpoint=test_url,
                            evidence=r.output[:2000],
                            repro=f"curl -g '{test_url}'",
                            impact="DB read/write possible via error-based SQLi", cvss=9.0,
                            status="confirmed")
                        break
                    if r.ok and PROBE_ID in r.output:
                        candidates += 1
                        await self.record(title=f"sqli probe reflected (needs verification) param={pname}",
                                          severity="medium", category="sqli", endpoint=test_url,
                                          evidence=r.output[:800], status="candidate")
        return f"sqli: {confirmed} confirmed, {candidates} candidates over {len(targets)} urls"

    async def a_test_xss(self, max_urls: int = 30) -> str:
        targets = await self._prepare_param_targets(max_urls)
        confirmed, candidates = 0, 0
        exec_payload = f'"><img src=x onerror=window.__dvhit=1>'
        for url, params in targets:
            p = urlparse(url)
            for pname in list(params.keys())[:4]:
                for payload in XSS_PAYLOADS:
                    q = dict(params)
                    q[pname] = payload
                    test_url = f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"
                    r = await self.tk.fetch(test_url, max_bytes=60000)
                    self.step(0.25)
                    if not r.ok:
                        continue
                    body = r.output
                    escaped = (payload.replace("<", "&lt;").replace(">", "&gt;") in body
                               and payload not in body)
                    if payload in body and not escaped:
                        ct = r.meta.get("headers", {}).get("content-type", "")
                        html = "html" in ct or "<html" in body.lower()[:2000]
                        executed = False
                        if html and self.tk.browser:
                            executed = await self._xss_execute(
                                f"{p.scheme}://{p.netloc}{p.path}", pname, params)
                        if html and executed:
                            confirmed += 1
                            await self.record(title=f"reflected XSS in parameter '{pname}'",
                                              severity="high", category="xss", endpoint=test_url,
                                              evidence=body[:1500],
                                              repro=f"open in browser: {f'{p.scheme}://{p.netloc}{p.path}?'}{urlencode({**params, pname: exec_payload})}",
                                              impact="Session theft, phishing via executed JS",
                                              cvss=7.5, status="confirmed")
                        elif html:
                            candidates += 1
                            await self.record(title=f"unescaped reflection, no execution (CSP/context?) param={pname}",
                                              severity="medium", category="xss", endpoint=test_url,
                                              evidence=body[:600], status="candidate")
                        else:
                            candidates += 1
                            await self.record(title=f"xss payload reflected non-HTML param={pname}",
                                              severity="low", category="xss", endpoint=test_url,
                                              evidence=body[:500], status="candidate")
                        break
        return f"xss: {confirmed} confirmed, {candidates} candidates over {len(targets)} urls"

    async def _xss_execute(self, base: str, pname: str, params: dict) -> bool:
        """Real browser execution check: injects an onerror payload and looks for
        the marker the payload would set. Escaped output never fires."""
        try:
            q = dict(params)
            q[pname] = '"><img src=x onerror=window.__dvhit=1>'
            url = f"{base}?{urlencode(q)}"
            self.tk.guard.check_url(url)
            ctx = await self.tk._pctx()
            page = await ctx.new_page()
            try:
                await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                await page.wait_for_timeout(800)
                hit = await page.evaluate("() => window.__dvhit === 1")
                return bool(hit)
            except Exception:
                return False
            finally:
                await page.close()
        except Exception:
            return False

    async def a_path_brute(self, max_hosts: int = 4) -> str:
        common = "/home/nil/projects/deep-diver/wordlists/common.txt"
        import os
        if not os.path.exists(common):
            return "wordlist missing"
        found = 0
        for host in sorted(self.surf.hosts)[:max_hosts]:
            base = host.rstrip("/") + "/FUZZ"
            r = await self.tk.ffuf(base, common,
                                   mc="200,201,204,301,302,307,401,403,405")
            self.step()
            for line in r.output.splitlines():
                m = re.match(r"(\d+)\s+(\d+)B\s+(.*)", line)
                if not m:
                    continue
                status, size, url = m.groups()
                url = url.strip()
                if url and urlparse(url).path not in ("/", ""):
                    self.surf.urls.add(url)
                    found += 1
                    if status in ("200", "301", "302", "401", "403"):
                        await self.record(title=f"hidden path {urlparse(url).path}",
                                          severity="informational", category="recon",
                                          endpoint=url, evidence=f"HTTP {status} {size}B",
                                          status="candidate")
        return f"path-brute: {found} hidden paths added"

    async def a_js_secrets(self) -> str:
        """Scan discovered JS files for leaked secrets/endpoints via trufflehog."""
        jsfiles = [u for u in self.surf.urls if u.rstrip().endswith(".js")]
        if not jsfiles:
            for host in sorted(self.surf.hosts)[:5]:
                r = await self.tk.fetch(host, max_bytes=200000)
                if r.ok:
                    body = r.output
                    for m in re.finditer(r"""(?:src|href)=["']([^"']+\.js)["']""", body):
                        u = urllib.parse.urljoin(host, m.group(1))
                        try:
                            self.tk.guard.check_url(u)
                            jsfiles.append(u)
                        except Exception:
                            pass
            jsfiles = sorted(set(jsfiles))
        if not jsfiles:
            return "no js files"
        hits = 0
        secrets_re = re.compile(
            r"""(aws_access_key_id|secret_access_key|api[_-]?key|password|passwd|token|bearer|authorization|private[_-]?key|client[_-]?secret)""", re.I)
        url_re = re.compile(r"""["'`](/(?:api|v\d|admin|auth|internal|debug)[A-Za-z0-9_\-./{}?$:=]*?)["'`]""")
        for u in jsfiles[:25]:
            r = await self.tk.fetch(u, max_bytes=700000)
            self.step(0.2)
            if not r.ok:
                continue
            body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
            for m in secrets_re.finditer(body):
                ctx = body[max(0, m.start() - 60):m.end() + 120]
                if re.search(r"[=:]\s*['\"]?[A-Za-z0-9+/=._\-]{16,}", ctx) and \
                        any(w in ctx.lower() for w in
                            ("key", "token", "passw", "secret", "bearer", "authorization")) and \
                        "<html" not in body.lower()[:3000]:
                    hits += 1
                    await self.record(title=f"possible secret in JS {urlparse(u).path}",
                                      severity="medium", category="secrets", endpoint=u,
                                      evidence=ctx[:400], status="candidate")
                    break
            for em in url_re.finditer(body):
                ep = em.group(1)
                base = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                full = base + ep.split("?")[0]
                try:
                    self.tk.guard.check_url(full)
                    self.surf.js_endpoints.add(full)
                except Exception:
                    self.surf.js_endpoints.add(ep)
        return f"js-secrets: {hits} candidates, +{len(self.surf.js_endpoints)} endpoints"

    async def a_test_open_redirect(self, max_urls: int = 20) -> str:
        confirmed = 0
        targets = await self._prepare_param_targets(max_urls)
        redirectish = ("url", "redirect", "next", "return", "to", "dest", "continue", "redir", "goto", "callback")
        for url, params in targets:
            p = urlparse(url)
            for pname in list(params.keys()):
                if not any(k in pname.lower() for k in redirectish):
                    continue
                for payload in REDIRECT_PAYLOADS:
                    q = dict(params)
                    q[pname] = payload
                    test_url = f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"
                    r = await self.tk.fetch(test_url, follow=False, max_bytes=2000)
                    self.step(0.25)
                    if r.meta.get("status", 0) in (301, 302, 303, 307, 308):
                        loc = r.meta.get("headers", {}).get("location", "")
                        if "deepdiver-redirect-test" in loc:
                            confirmed += 1
                            await self.record(title=f"open redirect via '{pname}'",
                                              severity="medium", category="open-redirect",
                                              endpoint=test_url, evidence=f"Location: {loc}",
                                              repro=f"curl -i '{test_url}'",
                                              impact="Phishing via trusted domain redirect",
                                              cvss=5.4, status="confirmed")
        return f"open-redirect: {confirmed} confirmed"

    async def a_test_ssrf(self, max_urls: int = 15) -> str:
        confirmed, candidates = 0, 0
        targets = await self._prepare_param_targets(max_urls)
        urlish = ("url", "uri", "src", "href", "fetch", "api_url", "endpoint", "image", "file", "path", "host")
        for url, params in targets:
            p = urlparse(url)
            for pname in list(params.keys()):
                if not any(k in pname.lower() for k in urlish):
                    continue
                for meta_url in ("http://169.254.169.254/latest/meta-data/",
                                 "http://169.254.169.254/metadata/v1.json",
                                 "http://metadata.google.internal/computeMetadata/v1/"):
                    q = dict(params)
                    q[pname] = meta_url
                    test_url = f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"
                    r = await self.tk.fetch(test_url, max_bytes=20000)
                    self.step(0.25)
                    if r.ok:
                        body = r.output.lower()
                        if any(m in body for m in SSRF_MARKERS):
                            confirmed += 1
                            await self.record(title=f"SSRF via '{pname}' reaches cloud metadata",
                                              severity="critical", category="ssrf", endpoint=test_url,
                                              evidence=r.output[:2000], repro=f"curl -g '{test_url}'",
                                              impact="Cloud metadata read -> credential theft", cvss=9.1,
                                              status="confirmed")
                            break
        return f"ssrf: {confirmed} confirmed"

    async def a_test_path_traversal(self, max_urls: int = 20) -> str:
        confirmed, candidates = 0, 0
        targets = await self._prepare_param_targets(max_urls)
        fileish = ("file", "path", "doc", "folder", "dir", "template", "page", "include", "layout")
        payloads = ["....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "file:///etc/passwd"]
        for url, params in targets:
            p = urlparse(url)
            for pname in list(params.keys()):
                if not any(k in pname.lower() for k in fileish):
                    continue
                for payload in payloads:
                    q = dict(params)
                    q[pname] = payload
                    test_url = f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"
                    r = await self.tk.fetch(test_url, max_bytes=8000)
                    self.step(0.25)
                    if r.ok and re.search(r"root:.*:0:0:|daemon:.*:/sbin/nologin", r.output):
                        confirmed += 1
                        await self.record(title=f"path traversal via '{pname}' reads /etc/passwd",
                                          severity="high", category="path-traversal", endpoint=test_url,
                                          evidence=r.output[:1500], repro=f"curl -g '{test_url}'",
                                          impact="Arbitrary file read", cvss=8.0, status="confirmed")
                        break
        return f"path-traversal: {confirmed} confirmed"

    async def a_http_method_fuzz(self, max_urls: int = 15) -> str:
        interesting = []
        for u in self.surf.urls:
            p = urlparse(u)
            if p.path.rstrip("/") and p.query:
                interesting.append(u)
        found = 0
        for u in interesting[:max_urls]:
            base = u.split("?")[0]
            for method in ("PUT", "DELETE", "PATCH"):
                key = f"mf:{method}:{base}"
                if key in self.surf.explored_actions:
                    continue
                self.surf.explored_actions.add(key)
                gr = await self.tk.fetch(base, method="GET", max_bytes=1000)
                ar = await self.tk.fetch(base, method=method, max_bytes=1000)
                self.step(0.2)
                gs, as_ = gr.meta.get("status", 0), ar.meta.get("status", 0)
                if gs == 405 and as_ in (200, 201, 204):
                    found += 1
                    await self.record(title=f"HTTP {method} allowed where GET is 405",
                                      severity="low", category="misconfig", endpoint=base,
                                      evidence=f"GET->{gs} {method}->{as_}", status="candidate")
                elif as_ in (200, 204) and gs in (403, 401):
                    found += 1
                    await self.record(title=f"auth bypass: {method} bypasses access control",
                                      severity="medium", category="auth", endpoint=base,
                                      evidence=f"GET->{gs} {method}->{as_}",
                                      impact="Possible BAC bypass", status="candidate")
        return f"method-fuzz: {found} interesting across {min(max_urls, len(interesting))} urls"

    async def a_admin_probe(self) -> str:
        """Check for unauthenticated admin/debug panels (no credential attacks)."""
        found = 0
        for host in sorted(self.surf.hosts)[:10]:
            base = host.rstrip("/")
            for path in ("/admin/", "/manager/html", "/console", "/_debug", "/api/admin",
                         "/internal/", "/status", "/metrics", "/env", "/info"):
                url = base + path
                r = await self.tk.fetch(url, max_bytes=3000)
                self.step(0.1)
                if r.ok and r.meta.get("status") == 200:
                    body = r.output[200:1200].lower()
                    if any(m in body for m in ("admin", "console", "debug", "metrics", "status", "environment")):
                        found += 1
                        await self.record(title=f"unauthenticated panel exposed at {path}",
                                          severity="medium", category="auth", endpoint=url,
                                          evidence=r.output[:1200], status="candidate")
        return f"admin-probe: {found} candidates"
