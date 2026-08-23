from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from urllib.parse import urlparse

from . import BaseAgent


class Scout(BaseAgent):
    name = "scout"

    async def run(self, plan: dict) -> list[str]:
        """plan keys: target (domain or url). Enumerates subdomains, probes live
        hosts, scans ports, fingerprints tech. Returns list of action summaries."""
        target = plan.get("target") or self.surf.root_target
        p = urlparse(target if "://" in target else f"http://{target}")
        apex = p.hostname or target
        self.surf.root_target = apex
        summaries = []
        is_ip = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", apex) is not None or apex == "localhost"

        if not self.surf.hosts:
            if is_ip or (p.scheme and p.port):
                seed = f"{p.scheme or 'http'}://{p.netloc if p.netloc else apex}"
                await self.say(f"single-host target: seeding {seed}")
                self.surf.hosts.add(seed.rstrip("/"))
            else:
                await self.say(f"enumerating subdomains for {apex}")
                r = await self.tk.subfinder(apex, passive_only=True)
                self.step()
                subs = [s for s in r.output.splitlines() if s.strip()]
                if apex not in subs:
                    subs.append(apex)
                await self.say(f"subfinder found {len(subs)} hosts")
                if subs:
                    await self._probe_live(subs)
                    summaries.append(f"enumerated+probed {len(subs)} hosts, {len(self.surf.hosts)} live")

        if not any(self.surf.ports.values()) and self.surf.hosts:
            await self._port_scan(list(self.surf.hosts)[:15])
            summaries.append("port scan complete")

        if not self.surf.tech and self.surf.hosts:
            await self._fingerprint(list(self.surf.hosts)[:25])
            summaries.append(f"fingerprinted tech on {len(self.surf.tech)} hosts")

        return summaries or ["no live hosts discovered"]

    async def _probe_live(self, hosts: list[str]):
        hosts = [h for h in hosts if self.tk.guard.is_host_allowed(h)]
        if not hosts:
            await self.say("no in-scope hosts to probe")
            return
        lst_path = f"{self.tk.workdir}/hosts.txt"
        with open(lst_path, "w") as f:
            f.write("\n".join(hosts))
        r = await self.tk.run_external_tool(
            "httpx", ["-l", lst_path, "-silent", "-status-code", "-title",
                      "-tech-detect", "-content-length", "-json", "-follow-redirects"],
            timeout=300)
        self.step()
        for line in r.output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url", "")
            if not url:
                continue
            host = urlparse(url).hostname or ""
            if not self.tk.guard.is_host_allowed(host):
                continue
            self.surf.hosts.add(url.rstrip("/"))
            if data.get("title"):
                self.surf.titles[url] = data["title"]
            tech = data.get("tech", [])
            if tech:
                self.surf.tech[url] = ", ".join(tech[:8])
        await self.say(f"{len(self.surf.hosts)} live hosts confirmed")

    async def _port_scan(self, hosts: list[str]):
        bare = []
        for h in hosts:
            try:
                host = urlparse(h).hostname or h
                bare.append(host)
            except Exception:
                bare.append(h)
        bare = sorted(set(bare))
        lst = f"{self.tk.workdir}/portscan.txt"
        with open(lst, "w") as f:
            f.write("\n".join(bare))
        r = await self.tk.run_external_tool(
            "naabu", ["-list", lst, "-silent", "-top-ports", "200",
                      "-rate", str(max(1, int(self.tk.gov.rps) * 10)), "-json"],
            timeout=300)
        self.step()
        for line in r.output.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = d.get("host") or d.get("ip", "")
            port = d.get("port")
            if host and port:
                self.surf.ports[host].append(int(port))
        open_count = sum(len(v) for v in self.surf.ports.values())
        await self.say(f"naabu: {open_count} open ports across {len(self.surf.ports)} hosts")

    async def _fingerprint(self, hosts: list[str]):
        for h in hosts:
            if h in self.surf.tech:
                continue
            r = await self.tk.fetch(h, max_bytes=20000)
            if r.ok:
                hdr = r.meta.get("headers", {})
                sig = []
                for k in ("server", "x-powered-by", "x-aspnet-version"):
                    v = hdr.get(k.lower())
                    if v:
                        sig.append(f"{k}:{v}")
                if sig:
                    self.surf.tech[h] = "; ".join(sig)
            self.step(0.2)
