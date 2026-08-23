"""ScopeGuard: default-deny enforcement of target scope.

Every network-touching tool routes through `guard.check_host()` /
`check_url()` before issuing a request. The LLM can never bypass this:
the registry in tools.py calls these unconditionally.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class ScopeViolation(Exception):
    pass


class ScopeGuard:
    # recon infrastructure (cert transparency, IP geolocation, DNS-over-HTTPS).
    # Read-only queries against public services; never probed/attacked.
    HELPER_HOSTS = ("crt.sh", "ipinfo.io", "api.ipify.org", "dns.google",
                    "cloudflare-dns.com", "rapiddns.io", "www.censys.io")

    def __init__(self):
        self.domains: set[str] = set()      # apex allowlist (apex covers subdomains)
        self.hosts: set[str] = set()        # exact hosts (e.g. IPs, localhost)
        self.allow_private: bool = False    # labs mode: allow 127.0.0.0/8, 172.16/12, 192.168/16, 10/8, link-local
        self.excluded: set[str] = set()     # explicit deny (subdomains/domains)
        self.protocols = {"http", "https"}

    def configure(self, scope_text: str):
        """Accepts newline/comma separated targets: domains, IPs, URLs.
        Lines starting with `-` are exclusions. Line `!private` enables lab mode."""
        self.domains.clear(); self.hosts.clear(); self.excluded.clear()
        self.allow_private = False
        for raw in re.split(r"[,\n;]+", scope_text):
            line = raw.strip()
            if not line:
                continue
            if line in ("!private", "private", "labs"):
                self.allow_private = True
                continue
            exclude = line.startswith("-")
            line = line.lstrip("-").strip()
            if "://" in line:
                host = urlparse(line).hostname or ""
            else:
                host = line.split("/")[0].split(":")[0]
            host = host.lower().strip(".")
            if not host:
                continue
            if exclude:
                self.excluded.add(host)
                continue
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or host in ("localhost",):
                self.hosts.add(host)
            else:
                self.domains.add(host)

    def is_host_allowed(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        if host in self.HELPER_HOSTS:
            return True
        for ex in self.excluded:
            if host == ex or host.endswith("." + ex):
                return False
        if host in self.hosts:
            return self._ip_ok(host)
        try:
            ip = ipaddress.ip_address(host)
            return self._ip_ok(str(ip))
        except ValueError:
            pass
        return any(host == d or host.endswith("." + d) for d in self.domains - self.excluded)

    def _ip_ok(self, addr: str) -> bool:
        if addr in ("localhost", "127.0.0.1"):
            return self.allow_private
        if addr in self.hosts:
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return self.allow_private
        return any(addr == h for h in self.hosts)

    def check_host(self, host: str):
        if not self.is_host_allowed(host):
            raise ScopeViolation(f"host out of scope: {host!r}")

    def check_url(self, url: str):
        try:
            p = urlparse(url)
        except ValueError:
            raise ScopeViolation(f"unparseable url: {url!r}")
        if p.scheme not in self.protocols:
            raise ScopeViolation(f"scheme blocked: {p.scheme!r}")
        if not p.hostname:
            raise ScopeViolation(f"no host in url: {url!r}")
        self.check_host(p.hostname)
        return p
