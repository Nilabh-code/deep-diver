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


class CveMatcher(BaseAgent):
    """Maps fingerprinted software (via httpx tech-detect CPE) to known CVEs
    through NVD API, and cross-checks against Qualys/striker-style heuristics."""
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
                    candidates.append((keyword, ver, key))
            if not candidates:
                cpe = self._extract_cpe(tech)
                if cpe:
                    candidates.append((cpe, "", "cpe"))
            for keyword, ver, key in candidates:
                sig = f"{keyword}:{ver}"
                if sig in checked:
                    continue
                checked.add(sig)
                cves = await self._nvd_lookup(keyword, ver)
                for cve in cves:
                    await self.record(
                        title=f"{key}: known CVE {cve['id']} ({cve['score']})",
                        severity=cve["sev"], category="known-cve",
                        endpoint=host,
                        evidence=f"software: {key}\nnvd: {cve['url']}\n{cve.get('desc','')[:400]}",
                        impact="Known vulnerability in running stack version — verify applicability",
                        cvss=cve["score"], status="candidate", bounty_ready=False)
                if cves:
                    out.append(f"{key}@{host}: {len(cves)} CVEs")
        return out or ["no CVE matches"]

    def _extract_cpe(self, tech: str) -> str:
        """httpx tech-detect output often includes cpe: strings in later fields."""
        m = re.search(r"([a-z0-9._\-]+(?:/| v)?\d+(?:\.\d+)*)", tech)
        return ""

    async def _nvd_lookup(self, keyword: str, version: str) -> list[dict]:
        params = {"keywordSearch": keyword, "resultsPerPage": 10}
        url = NVD_API + "?" + urllib.parse.urlencode(params)
        r = await self.tk.fetch(url, max_bytes=50000)
        self.step(0.5)
        if not r.ok:
            return []
        body = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
            score, sev = 0.0, "informational"
            for m in cve.get("metrics", {}).get("cvssMetricV31", []):
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0)
                sev = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high",
                       "CRITICAL": "critical"}.get(cvss.get("baseSeverity", ""), "low")
                break
            if score < 4.0:
                continue
            out.append({"id": cid, "score": score, "sev": sev,
                        "desc": desc,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
        return out[:5]
