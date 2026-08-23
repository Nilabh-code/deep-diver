from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

from . import BaseAgent

CDN_HEADER_SIGS = (
    "cf-ray", "cf-cache-status", "x-azure-ref", "x-msedge-ref",
    "x-cache-lookup", "x-amz-cf-id", "x-served-by", "x-fastly-request-id",
    "x-akamai-transformed", "akamai-", "cloudflare", "x-cache:",
)
CDN_ORGS = ("cloudflare", "amazon", "azure", "microsoft", "fastly", "akamai",
            "google", "edgecast", "cdn", "incapsula", "imperva")


def looks_cdn(headers: dict, via_ipinfo_org: str = "") -> bool:
    low = {k.lower(): str(v).lower() for k, v in headers.items()}
    if any(sig in low for sig in CDN_HEADER_SIGS):
        return True
    server = low.get("server", "")
    if any(s in server for s in ("cloudflare", "akamai", "amazon", "ats", "nginx-azure")):
        return True
    org = via_ipinfo_org.lower()
    return any(o in org for o in CDN_ORGS)


class OriginHunter(BaseAgent):
    """Unmask the origin behind CDN/WAF/load-balancers.

    Strategy (standard origin-IP discovery):
    1. crt.sh certificate transparency -> every hostname ever certed for the apex
    2. resolve each host -> A-records; filter out CDN-owned ranges
    3. candidate IPs verified by curl --resolve with Host/SNI matching the target,
       compared against the CDN-served page fingerprint (title + markers)
    4. org check via ipinfo.io for the remaining candidates
    Origins found get added to the surface for direct exploitation.
    """
    name = "origin"

    async def run(self, plan: dict) -> list[str]:
        apex = plan.get("apex") or self.surf.root_target
        if apex.startswith("www."):
            apex = apex[4:]
        out = []
        # 1. cert transparency
        await self.say(f"querying crt.sh for *.{apex} certificates")
        names = await self._crtsh_names(apex)
        await self.say(f"crt.sh: {len(names)} unique hostnames")
        # 2. resolve all + collect non-CDN IPs
        candidates: dict[str, set[str]] = {}
        for host in sorted(names)[:120]:
            try:
                self.tk.guard.check_host(host)
            except Exception:
                continue
            ips = await self._resolve(host)
            for ip in ips:
                candidates.setdefault(ip, set()).add(host)
        await self.say(f"resolved {len(candidates)} unique IPs across cert'd hosts")
        # 3. filter by ipinfo org
        real_candidates = {}
        for ip, hosts in candidates.items():
            if not self._is_public(ip):
                continue
            org = await self._ipinfo_org(ip)
            if org and any(o in org.lower() for o in CDN_ORGS):
                continue
            real_candidates[ip] = (hosts, org)
        await self.say(f"{len(real_candidates)} non-CDN candidate IPs after org check")
        # 4. verify with --resolve fingerprint match
        ref = await self._fingerprint(plan.get("web_host") or f"https://www.{apex}")
        for ip, (hosts, org) in list(real_candidates.items())[:15]:
            if self.steps["used"] >= self.steps["max"]:
                break
            matched_host = await self._verify_ip(ip, hosts, ref)
            if matched_host:
                origin_url = f"https://{matched_host}"
                self.surf.hosts.add(origin_url)
                self.surf.add_note(f"ORIGIN FOUND {ip} serves {matched_host} (org={org})")
                await self.record(
                    title=f"origin IP {ip} exposed behind CDN ({org or 'unknown org'})",
                    severity="high", category="origin-disclosure",
                    endpoint=f"{ip} / {matched_host}",
                    evidence=f"curl --resolve {matched_host}:443:{ip} matches CDN fingerprint; "
                             f"direct access bypasses WAF/rate-limit controls",
                    repro=f"curl -sk --resolve {matched_host}:443:{ip} https://{matched_host}/ -o /dev/null -w '%{{http_code}}'",
                    impact="WAF/CDN bypass — direct origin access", cvss=7.0, status="confirmed")
                out.append(f"origin {ip} verified for {matched_host}")
            else:
                self.surf.add_note(f"origin candidate {ip} ({org}) did not match fingerprint")
        return out or ["no origins unmasked"]

    async def _crtsh_names(self, apex: str) -> set[str]:
        r = await self.tk.fetch(f"https://crt.sh/?q=%25.{apex}&output=json", max_bytes=2_000_000,
                                follow=True)
        if not r.ok:
            return set()
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        names: set[str] = set()
        try:
            data = json.loads(body)
            for entry in data:
                for v in (entry.get("name_value") or "").split("\n"):
                    v = v.strip().lower().lstrip("*.")
                    if v and (v == apex or v.endswith("." + apex)) and "*" not in v:
                        names.add(v)
        except json.JSONDecodeError:
            for m in re.finditer(rf"[a-z0-9.\-]+\.{re.escape(apex)}", body):
                names.add(m.group(0))
        return names

    async def _resolve(self, host: str) -> list[str]:
        import socket
        try:
            return await __import__("asyncio").to_thread(
                lambda: [a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)])
        except Exception:
            return []

    def _is_public(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
        except ValueError:
            return False

    async def _ipinfo_org(self, ip: str) -> str:
        r = await self.tk.fetch(f"https://ipinfo.io/{ip}/json", max_bytes=2000)
        if not r.ok:
            return ""
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        try:
            return json.loads(body).get("org", "")
        except json.JSONDecodeError:
            return ""

    async def _fingerprint(self, url: str) -> dict | None:
        r = await self.tk.fetch(url, max_bytes=100000)
        if not r.ok:
            return None
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        title = (re.search(r"<title>([^<]*)</title>", body, re.I) or [None, ""])
        markers = set(re.findall(r'/_next/static/([A-Za-z0-9_\-]+)', body))
        return {"title": title[1].strip() if len(title) > 1 else "",
                "markers": markers,
                "headers": r.meta.get("headers", {}),
                "len_cls": len(body) // 5000}

    async def _verify_ip(self, ip: str, hosts: set[str], ref: dict | None) -> str | None:
        if ref is None:
            return None
        for host in sorted(hosts)[:5]:
            try:
                self.tk.guard.check_host(host)
            except Exception:
                continue
            cmd = ["curl", "-sk", "--max-time", "12", "--resolve", f"{host}:443:{ip}",
                   f"https://{host}/", "-D-", "-o", "/tmp/opencode/origin_body.html"]
            r = await self.tk.run_cmd(cmd, timeout=20)
            if not r.ok:
                continue
            try:
                with open("/tmp/opencode/origin_body.html", encoding="utf-8", errors="replace") as f:
                    body = f.read(120000)
            except Exception:
                continue
            title = re.search(r"<title>([^<]*)</title>", body, re.I)
            markers = set(re.findall(r'/_next/static/([A-Za-z0-9_\-]+)', body))
            if len(body) < 200:
                continue
            score = 0
            if ref["title"] and title and ref["title"] == title.group(1).strip():
                score += 2
            if ref["markers"] & markers:
                score += 2
            if len(body) // 5000 == ref["len_cls"]:
                score += 1
            if score >= 2:
                return host
        return None
