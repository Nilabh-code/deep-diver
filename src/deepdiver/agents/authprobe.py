from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qsl

from . import BaseAgent


class AuthProbe(BaseAgent):
    """strix-style: given credentials, authenticate through the UI (Playwright),
    capture session cookies/tokens, then probe discovered endpoints for IDOR and
    broken access control by swapping object IDs."""
    name = "authprobe"

    def __init__(self, *args, credentials: dict | None = None):
        super().__init__(*args)
        self.creds = credentials or {}
        self.session_cookies: dict[str, str] = {}
        self.auth_headers: dict[str, str] = {}

    async def run(self, plan: dict) -> list[str]:
        form_url = plan.get("login_url") or self._find_login_url()
        if not form_url:
            return ["no login form/url found to authenticate"]
        if not self.creds:
            await self.say("no credentials configured — probing pre-auth BAC only")
            return await self._preauth_bac(plan)
        ok = await self._login(form_url)
        if not ok:
            return ["login failed with provided credentials"]
        results = await self._idor_sweep(plan)
        return results

    def _find_login_url(self) -> str:
        for form in self.surf.forms:
            inputs = [i.lower() for i in form.get("inputs", [])]
            if any("password" in i for i in inputs) and \
                    any("email" in i or "user" in i for i in inputs):
                return form["page"]
        for u in self.surf.urls:
            lu = u.lower()
            if "/login" in lu or "/sign-in" in lu or "/signin" in lu or "/auth" in lu:
                return u
        return ""

    async def _login(self, url: str) -> bool:
        try:
            self.tk.guard.check_url(url)
        except Exception:
            return False
        ctx = await self.tk._pctx()
        page = await ctx.new_page()
        try:
            await page.goto(url, timeout=25000, wait_until="domcontentloaded")
            await page.wait_for_timeout(500)
            filled = 0
            email = self.creds.get("email", "")
            pw = self.creds.get("password", "")
            for sel, val in (([f"input[type=email]", "input[name*=email i]", "input[name*=user i]"],
                              email),
                             (["input[type=password]"], pw)):
                for s in sel:
                    el = await page.query_selector(s)
                    if el:
                        await el.fill(val)
                        filled += 1
                        break
            if filled < 2:
                await page.close()
                return False
            for sel in ("button[type=submit]", "input[type=submit]", "button:has-text('Log in')",
                        "button:has-text('Sign in')", "button"):
                btn = await page.query_selector(sel)
                if btn:
                    await btn.click(timeout=6000)
                    break
            await page.wait_for_timeout(2500)
            cookies = await ctx.cookies()
            for c in cookies:
                self.session_cookies[c["name"]] = c["value"]
            # try to capture bearer from localStorage
            try:
                tok = await page.evaluate("() => localStorage.getItem('token') || localStorage.getItem('access_token') || ''")
                if tok:
                    self.auth_headers["Authorization"] = f"Bearer {tok}"
            except Exception:
                pass
            await page.close()
            ok = bool(self.session_cookies or self.auth_headers)
            if ok:
                self.surf.add_note(f"authenticated session captured ({len(self.session_cookies)} cookies)")
            return ok
        except Exception as e:
            await self.say(f"login error: {e}")
            try:
                await page.close()
            except Exception:
                pass
            return False

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())

    async def _preauth_bac(self, plan: dict) -> list[str]:
        """Probe obviously sensitive API paths WITHOUT auth — catches what even an
        unauthenticated attacker gets (route-breaker style)."""
        issues = []
        id_paths = ("/users/1", "/user/1", "/accounts/1", "/orders/1",
                    "/products/1", "/customers/1", "/sessions/1")
        for host in sorted(self.surf.hosts)[:5]:
            base = host.rstrip("/")
            api_roots = [f"{base}/api", f"{base}/api/v1", base]
            for root in api_roots:
                for p in id_paths:
                    url = root + p
                    r = await self.tk.fetch(url, max_bytes=2000)
                    self.step(0.15)
                    st = r.meta.get("status", 0)
                    if st == 200:
                        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                        if any(k in body.lower() for k in ('"email"', '"password', '"phone"', '"address')):
                            issues.append(url)
                            await self.record(
                                title=f"unauthenticated object access at {urlparse(url).path}",
                                severity="high", category="idor", endpoint=url,
                                evidence=body[:800],
                                repro=f"curl -sk '{url}'",
                                impact="Direct object reference readable without auth (IDOR)",
                                cvss=7.5, status="confirmed", bounty_ready=True)
        return [f"preauth-bac: {len(issues)} IDOR hits"] if issues else ["preauth-bac: clean"]

    async def _idor_sweep(self, plan: dict) -> list[str]:
        hits = 0
        tested = 0
        hdrs = {**self.auth_headers}
        cookie = self._cookie_header()
        if cookie:
            hdrs["Cookie"] = cookie
        for u in sorted(self.surf.urls):
            if self.steps["used"] >= self.steps["max"]:
                break
            q = dict(parse_qsl(urlparse(u).query))
            idish = {k for k in q if re.search(r"(?i)(^|_|\b)(id|uid|user|account|order|session|token|ref)(_|$|\b)", k)
                     and re.search(r"^\d+$", q[k] or "")}
            if not idish:
                continue
            tested += 1
            base = u
            for k in idish:
                orig = q[k]
                try:
                    flipped = str(int(orig) + 1)
                except ValueError:
                    continue
                q2 = dict(q)
                q2[k] = flipped
                test_url = base.split("?")[0] + "?" + "&".join(f"{a}={v}" for a, v in q2.items())
                r = await self.tk.fetch(test_url, headers=hdrs, max_bytes=4000)
                self.step(0.2)
                st = r.meta.get("status", 0)
                if st == 200:
                    body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                    if len(body.strip()) > 50 and "error" not in body.lower()[:200]:
                        hits += 1
                        await self.record(
                            title=f"possible IDOR: {k}={orig} -> {flipped} returns other user's object",
                            severity="high", category="idor", endpoint=test_url,
                            evidence=body[:800], impact="Horizontal privilege escalation",
                            cvss=7.5, status="candidate")
                        break
        return [f"idor-sweep: {hits} hits over {tested} tested"]
