from __future__ import annotations

import asyncio
import json
import re
import socket
from urllib.parse import urlparse

from . import BaseAgent

PURE_CDN_ORGS = ("cloudflare", "fastly", "akamai", "cdn77", "cachefly",
                 "incapsula", "imperva", "edgecast", "bunnynet", "bunny.net",
                 "aws global accelerator", "cloudfront")


class OriginHunter(BaseAgent):
    """Unmask origins behind CDN/WAF/load-balancers.

    Pipeline:
    1. gather hostnames: cert transparency (crt.sh) + archive.org + otx, PLUS all
       hosts already known to the surface (subfinder output)
    2. resolve A-records for every hostname -> cluster into IP -> hosts
    3. drop pure-CDN IPs (cloudflare/fastly/akamai...); cloud-provider IPs
       (azure/aws/gcp) ARE origin candidates — real servers live there
    4. for each candidate IP, curl --resolve one of its hosts; any live service
       that responds directly (not via the fronting CDN) is an exposed origin
    5. extra comparison: host served through candidate IP vs through its normal
       DNS resolution — a difference confirms direct-origin access
    """
    name = "origin"

    async def run(self, plan: dict) -> list[str]:
        apex = plan.get("apex") or self.surf.root_target
        if apex.startswith("www."):
            apex = apex[4:]
        out = []
        names: set[str] = set()
        # known surface hosts
        for h in self.surf.hosts:
            try:
                hn = urlparse(h).hostname or ""
                if hn and (hn == apex or hn.endswith("." + apex)):
                    names.add(hn)
            except Exception:
                pass
        for source in (self._crtsh_names, self._archive_subdomains, self._alienvault_passive):
            try:
                got = await source(apex)
                if got:
                    names |= got
                    await self.say(f"{source.__name__}: {len(got)} hostnames")
            except Exception as e:
                await self.say(f"{source.__name__} err: {e}")
        await self.say(f"total hostnames to resolve: {len(names)}")
        clusters: dict[str, set[str]] = {}
        for host in sorted(names)[:200]:
            try:
                self.tk.guard.check_host(host)
            except Exception:
                continue
            for ip in await self._resolve(host):
                clusters.setdefault(ip, set()).add(host)
        await self.say(f"{len(clusters)} unique IPs across {len(names)} hosts")
        for ip, hosts in sorted(clusters.items()):
            if self.steps["used"] >= self.steps["max"]:
                break
            if not self._is_public(ip):
                continue
            org = await self._ipinfo_org(ip)
            if org and any(c in org.lower() for c in PURE_CDN_ORGS):
                self.surf.add_note(f"{ip} is pure CDN ({org}) — {len(hosts)} hosts fronted")
                continue
            res = await self._probe_cluster(ip, sorted(hosts), org)
            out.extend(res)
        return out or ["no direct origins unmasked"]

    async def _probe_cluster(self, ip: str, hosts: list[str], org: str) -> list[str]:
        found = []
        for host in hosts[:3]:
            probe = await self._curl_resolve(ip, host, "/")
            if probe is None:
                continue
            status, title, headers, length = probe
            if status not in (200, 301, 302, 401, 403, 500):
                continue
            # compare with normal-DNS resolution of the same host
            normal = await self._curl_normal(host)
            diff = ""
            if normal:
                n_status, n_title, _, _ = normal
                if n_status == status and n_title == title:
                    diff = "same-as-cdn-view"
                else:
                    diff = f"DIFFERS from CDN view ({n_status}/{n_title!r})"
            endpoint = f"https://{host} (ip {ip}, org={org or '?'})"
            await self.record(
                title=f"direct origin access: {host} -> {ip} ({'CDN-bypass' if 'DIFFERS' in diff else 'direct-service'})",
                severity="high" if "DIFFERS" in diff else "medium",
                category="origin-disclosure", endpoint=endpoint,
                evidence=f"curl --resolve {host}:443:{ip} -> HTTP {status} | title: {title!r}\n"
                         f"server headers: {json.dumps({k: v for k, v in (headers or {}).items() if k.lower() in ('server','x-powered-by','via','www-authenticate')}, indent=1)}\n"
                         f"body {length}B | comparison: {diff or 'n/a'}",
                repro=f"curl -sk --resolve {host}:443:{ip} https://{host}/ -o /dev/null -w '%{{http_code}}'",
                impact="WAF/CDN bypass: origin server reachable directly — rate limits, "
                       "WAF rules and IP allowlists on the front door do not apply",
                cvss=7.2 if "DIFFERS" in diff else 6.0, status="confirmed", bounty_ready=True)
            found.append(f"origin/service {host}@{ip}")
        return found

    async def _curl_resolve(self, ip: str, host: str, path: str):
        cmd = ["curl", "-sk", "--max-time", "12", "--resolve", f"{host}:443:{ip}",
               "-D-", f"https://{host}{path}", "-o", "/tmp/opencode/origin_body.html"]
        r = await self.tk.run_cmd(cmd, timeout=20)
        self.step(0.3)
        if not r.ok:
            return None
        head, _, body_part = r.output.partition("\r\n\r\n")
        if not head:
            return None
        lines = head.splitlines()
        try:
            status = int(lines[0].split()[1])
        except Exception:
            return None
        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, _, v = l.partition(":")
                headers[k.strip().lower()] = v.strip()
        try:
            with open("/tmp/opencode/origin_body.html", encoding="utf-8", errors="replace") as f:
                body = f.read(100000)
        except Exception:
            body = body_part
        title = re.search(r"<title[^>]*>([^<]{2,90})", body, re.I)
        return status, (title.group(1).strip() if title else ""), headers, len(body)

    async def _curl_normal(self, host: str):
        r = await self.tk.fetch(f"https://{host}/", max_bytes=100000)
        if not r.ok:
            return None
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        title = re.search(r"<title[^>]*>([^<]{2,90})", body, re.I)
        return r.meta.get("status", 0), (title.group(1).strip() if title else ""), \
               r.meta.get("headers", {}), len(body)

    async def _crtsh_names(self, apex: str) -> set[str]:
        import asyncio as _a
        for attempt in range(2):
            r = await self.tk.fetch(f"https://crt.sh/?q=%25.{apex}&output=json",
                                    max_bytes=2_000_000, follow=True)
            if r.ok:
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                if body.lstrip().startswith("["):
                    names: set[str] = set()
                    try:
                        for entry in json.loads(body):
                            for v in (entry.get("name_value") or "").split("\n"):
                                v = v.strip().lower().lstrip("*.")
                                if v and (v == apex or v.endswith("." + apex)) and "*" not in v:
                                    names.add(v)
                        return names
                    except json.JSONDecodeError:
                        pass
            await _a.sleep(3)
        return set()

    async def _archive_subdomains(self, apex: str) -> set[str]:
        url = (f"https://web.archive.org/cdx/search/cdx?url={apex}"
               f"&matchType=domain&output=json&fl=original&collapse=urikey&limit=3000")
        r = await self.tk.fetch(url, max_bytes=4_000_000, follow=True)
        names: set[str] = set()
        if not r.ok:
            return names
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        try:
            rows = json.loads(body)
            for row in rows[1:]:
                raw = row[0] if isinstance(row, list) else str(row)
                host = urlparse(raw).hostname
                if host and (host == apex or host.endswith("." + apex)):
                    names.add(host.lower())
        except (json.JSONDecodeError, IndexError):
            pass
        return names

    async def _alienvault_passive(self, apex: str) -> set[str]:
        r = await self.tk.fetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns",
            max_bytes=500000, follow=True)
        names: set[str] = set()
        if not r.ok:
            return names
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        try:
            for rec in json.loads(body).get("passive_dns", []):
                h = (rec.get("hostname") or "").lower()
                if rec.get("record_type") == "A" and h and (h == apex or h.endswith("." + apex)):
                    names.add(h)
        except json.JSONDecodeError:
            pass
        return names

    async def _resolve(self, host: str) -> list[str]:
        try:
            return await asyncio.to_thread(
                lambda: [a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)])
        except Exception:
            return []

    def _is_public(self, ip: str) -> bool:
        import ipaddress
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
