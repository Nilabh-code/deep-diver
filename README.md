# deep-diver

Autonomous multi-agent bug bounty hunter. Give it a URL you own or a bounty
program scope — it reconnoiters, crawls, unmasks CDN origins, hunts, verifies,
and writes a bounty-grade report with an executive summary.

## Quick start (self-service)

```bash
# dashboard — open, paste URL, LAUNCH HUNT
./start.sh                          # http://localhost:8911

# one-shot scan from terminal
./scan.sh https://target.example.com
./scan.sh https://target.example.com --budget 90 --recon-only
./scan.sh https://target.example.com --cred-email test@co.com --cred-password 'pw'
```

Reports land in `./runs/report-<runid>.md`.

## Agents

| agent | role |
|---|---|
| Conductor | LLM planner — batches moves, deterministic fallback cycle |
| Scout | subfinder (-all), httpx live probing, naabu ports, fingerprinting |
| Cartographer | katana + Playwright browser crawl, forms, XHR/API endpoints |
| OriginHunter | CDN/WAF unmask: crt.sh/archive.org/OTX hostnames → DNS → ipinfo org filtering → curl --resolve + bare-IP/Host verification + CDN-header diffing |
| ApiScanner | Next.js buildManifest, JS-chunk route harvest, GraphQL introspection, API wordlist brute, shadow-AI endpoints |
| CveMatcher | fingerprints → NVD CVE lookups (garak/pentest-gpt style vuln intel) |
| AiProbe | safe garak-style AI exposure: marker-prompt liveness, model-list leaks |
| AuthProbe | Playwright login with your creds → session capture → IDOR sweep (strix-style); pre-auth BAC probes when no creds |
| Hunter | takeover, sensitive files, SQLi, XSS (browser-execution confirmed), SSRF, path traversal, cmdi (time-based + marker), open redirect, method fuzz, CORS/clickjacking/cookie headers, downgrade, host-header, user enum, path brute, JS secrets |
| Verifier | re-tests every candidate, rejects WAF challenge pages + unreachable |
| Auditor | CVSS scoring, LLM executive summary, markdown report |

## Safety

- **Default-deny scope guard** in the tool layer — the LLM cannot escape it.
- Detection payloads only (markers/time-delays), no DoS, no brute force, no shells.
- `--recon-only`: enumeration only, zero attack probes.
- `--mode quiet|normal|aggressive` → rate governor caps every request.
- Kill switch in the dashboard.

## Install

```bash
uv sync && uv run playwright install chromium
# go tools (Arch: yaourt-style from bin)
go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,httpx/cmd/httpx,katana/cmd/katana,nuclei/v3/cmd/nuclei,naabu/v2/cmd/naabu}@latest
go install github.com/ffuf/ffuf/v2@latest
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
```

## Laws of the diver

1. Only targets in your written scope (bounty program, or assets you own).
2. Recon before hunting; verify before reporting.
3. Findings stay local until *you* submit them through the program's channel.
