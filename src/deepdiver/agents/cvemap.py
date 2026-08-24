from __future__ import annotations

import json
import re
import urllib.parse
from urllib.parse import urlparse

from . import BaseAgent

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# fingerprints we know deep-diver sees, mapped to NVD keyword searches
TECH_CVE_PROBES = {
    "signoz": ("signoz", "0.97"),
    "coolify": ("coolify", ""),
    "n8n": ("n8n", ""),
    "activepieces": ("activepieces", ""),
    "langfuse": ("langfuse", ""),
    "vaultwarden": ("vaultwarden bitwarden_rs", ""),
    "netbird": ("netbird", ""),
    "ollama": ("ollama", ""),
    "tina": ("tinacms", ""),
    "juice": ("juice shop", ""),
}

# best-effort live version endpoints: key -> (path, json field holding version)
VERSION_PROBES = {
    "langfuse": ("/api/public/health", "version"),
    "signoz": ("/api/v1/version", "version"),
    "netbird": ("/api/version", "version"),
    "vaultwarden": ("/api/version", None),
    "ollama": ("/api/version", "version"),
    "coolify": ("/api/v1/version", "version"),
}


def ver_tuple(v: str) -> tuple:
    parts = []
    for p in re.split(r"[.\-+_]", (v or "").strip()):
        m = re.match(r"(\d+)", p)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) or (0,)


def ver_in_range(v: str, start: str, end: str, end_inclusive: bool = False) -> bool:
    vt = ver_tuple(v)
    if start:
        st = ver_tuple(start)
        if vt < st:
            return False
    if end:
        et = ver_tuple(end)
        if end_inclusive:
            if vt > et:
                return False
        else:
            if vt >= et:
                return False
    return True


class CveMatcher(BaseAgent):
    """Maps fingerprinted software to known CVEs through the NVD API, THEN pins
    the result against the detected running version. A CVE is only recorded when
    the running version falls inside the NVD-published vulnerable range (or when
    no version could be determined, as an explicitly-unverified candidate).
    Version-out-of-range CVEs are never reported."""
    name = "cvematch"

    async def run(self, plan: dict) -> list[str]:
        out = []
        checked = set()
        for host in sorted(self.surf.hosts)[:30]:
            if self.steps["used"] >= self.steps["max"]:
                break
            tech = self.surf.tech.get(host, "")
            title = self.surf.titles.get(host, "").lower()
            url_path = urlparse(host).netloc.split(".")[0]
            candidates = []
            for key, (keyword, ver) in TECH_CVE_PROBES.items():
                if key in tech.lower() or key in title or key in url_path:
                    candidates.append((keyword, key))
            for keyword, key in candidates:
                if keyword in checked:
                    continue
                checked.add(keyword)
                running = await self._detect_version(host, key, tech, title)
                applicable, unknown_ver = await self._nvd_lookup(keyword, running)
                for cve in applicable:
                    await self.record(
                        title=f"{key}: known CVE {cve['id']} ({cve['score']})",
                        severity=cve["sev"], category="known-cve",
                        endpoint=host,
                        evidence=(f"software: {key}\nrunning version: {running or 'UNKNOWN'}\n"
                                  f"vulnerable range: {cve['range']}\nnvd: {cve['url']}\n"
                                  f"{cve.get('desc','')[:400]}"),
                        impact="Running stack version is inside the CVE's vulnerable range",
                        cvss=cve["score"], status="candidate", bounty_ready=False)
                if applicable:
                    out.append(f"{key}@{host}: {len(applicable)} applicable CVEs "
                               f"(version {running or '?'})")
                if unknown_ver:
                    self.surf.add_note(f"{key}@{host}: {unknown_ver} CVEs skipped — version "
                                       f"undetermined, check manually")
        return out or ["no applicable CVE matches"]

    async def _detect_version(self, host: str, key: str, tech: str, title: str) -> str:
        probe = VERSION_PROBES.get(key)
        if probe:
            path, field = probe
            r = await self.tk.fetch(host.rstrip("/") + path, max_bytes=4000)
            self.step(0.15)
            if r.ok:
                body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
                if field:
                    try:
                        v = json.loads(body).get(field, "")
                        if isinstance(v, str) and re.match(r"\d", v):
                            return v.split("+")[0].split("-")[0]
                    except (json.JSONDecodeError, AttributeError):
                        pass
                m = re.search(r"\"?(?:version|VERSION)\"?\s*[:=]\s*\"?(\d+\.\d+(?:\.\d+)*)", body)
                if m:
                    return m.group(1)
        m = re.search(re.escape(key) + r"[/ ]v?(\d+\.\d+(?:\.\d+)*)", tech + " " + title, re.I)
        if m:
            return m.group(1)
        cpe = re.search(r"cpe:[^:]*:[^:]*:[^:]*:[^:]*:([^:\\s]+):", tech)
        if cpe and re.match(r"\d", cpe.group(1)) and cpe.group(1) not in ("*", "-"):
            return cpe.group(1)
        return ""

    async def _nvd_lookup(self, keyword: str, running: str) -> tuple[list[dict], int]:
        """Returns (applicable CVEs, count-of-CVEs-with-CPE-ranges-that-excluded-us)."""
        params = {"keywordSearch": keyword, "resultsPerPage": 20}
        url = NVD_API + "?" + urllib.parse.urlencode(params)
        r = await self.tk.fetch(url, max_bytes=200000)
        self.step(0.5)
        if not r.ok:
            return [], 0
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return [], 0
        out, skipped = [], 0
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
            score, sev = 0.0, "informational"
            for m in cve.get("metrics", {}).get("cvssMetricV31", []) or \
                    cve.get("metrics", {}).get("cvssMetricV30", []):
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0)
                sev = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high",
                       "CRITICAL": "critical"}.get(cvss.get("baseSeverity", ""), "low")
                break
            if score < 4.0:
                continue
            start, end, end_inc = "", "", False
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cm in node.get("cpeMatch", []):
                        if not cm.get("vulnerable"):
                            continue
                        start = cm.get("versionStartIncluding", "") or start
                        if cm.get("versionEndExcluding"):
                            end, end_inc = cm["versionEndExcluding"], False
                        elif cm.get("versionEndIncluding"):
                            end, end_inc = cm["versionEndIncluding"], True
            if not running:
                if start or end:
                    continue
                out.append({"id": cid, "score": score, "sev": sev, "desc": desc,
                            "range": "no CPE range published",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
                continue
            if not (start or end):
                m = re.search(r"(?:before|prior to|earlier than|up to|through)\s+(\d+\.\d+(?:\.\d+)*)",
                              desc, re.I)
                if m:
                    end, end_inc = m.group(1), False
            if start or end:
                if not ver_in_range(running, start, end, end_inc):
                    skipped += 1
                    continue
                rng = f">={start or '0'} {'<=' if end_inc else '<'}{end or '∞'}"
            else:
                rng = "no range published — manual check needed"
            out.append({"id": cid, "score": score, "sev": sev, "desc": desc,
                        "range": rng,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
        return out[:8], skipped
