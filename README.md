# deep-diver

Multi-agent autonomous bug bounty hunter. Give it a company URL; it reconnoiters,
crawls, forms attack hypotheses, tests them safely, verifies, and writes a
bounty-grade report. Built for legal use against bug bounty programs and assets
you own — every tool call passes a default-deny scope guard.

## Architecture

```
                    ┌────────────┐
  you (dashboard)──▶│  Conductor │◀── LLM (any OpenAI-compatible endpoint)
                    └─────┬──────┘
                          │ plans the next move until exhausted
        ┌────────┬────────┼────────┬─────────┐
        ▼        ▼        ▼        ▼         ▼
     Scout  Cartographer Hunter  Verifier  Auditor
   subdomains  crawl    attack   confirm   CVSS +
   ports/tech  forms    probes   or reject  report
```

- **Conductor** — LLM-driven planner. Reads the attack surface state + history,
  emits the next single agent move. Deterministic fallback cycle if the model
  is silent, so the hunt never stalls.
- **Scout** — subfinder → httpx → naabu → tech fingerprinting.
- **Cartographer** — katana link crawl + Playwright browser crawl (JS-rendered
  pages, forms, XHR/API endpoints, JS-file endpoint extraction).
- **Hunter** — nuclei scans, takeover checks, sensitive files, SQLi/XSS/open-
  redirect/SSRF/path-traversal param probes, HTTP method fuzzing, unauth admin
  panels, path brute-force, JS secret scanning. Detection-only payloads;
  nothing destructive, no credential attacks.
- **Verifier** — re-tests every candidate, keeps only reproducible evidence.
- **Auditor** — CVSS scoring + markdown report per run.

**Scope guard** (`src/deepdiver/scope.py`): default-deny allowlist. Every
fetch/URL/host is asserted in-scope before any request leaves the process.
`!private` in the scope string permits localhost/private ranges (labs only).
The LLM cannot talk its way around the guard — it's enforced in the tool layer.

## Install

```bash
uv sync
uv run playwright install chromium

# external tools (Arch example)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/ffuf/ffuf/v2@latest
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
# sqlmap, trufflehog, dalfox optional — Hunter degrades gracefully without them
```

## Usage

Web dashboard (recommended):

```bash
uv run deepdiver serve --port 8911    # http://localhost:8911
```

Enter target, scope, and LLM endpoint (base URL + API key + model — any
OpenAI-compatible: local llama.cpp/ollama/unsloth, or cloud), then LAUNCH.
Live event feed, findings board, kill switch, markdown report.

Headless:

```bash
uv run deepdiver run https://target.example.com \
  --scope "target.example.com,-staging.target.example.com" \
  --base-url http://localhost:8888/v1 --api-key $KEY --model MODEL \
  --mode aggressive --budget 120
```

## Laws of the diver

1. Only targets you explicitly put in scope. The guard is default-deny.
2. Only bug bounty programs or assets you own/have written permission on.
3. Detection payloads only: markers, errors, harmless reflections. No DoS, no
   credential brute-force, no data exfiltration, no deployment of shells.
4. Rate-governed even in aggressive mode. Respect the program's policy.
5. Findings stay local until *you* submit them through the program's channel.

## Status

Built and validated against DVWA + OWASP Juice Shop in docker. This is an
aggressive research tool — review findings manually before any disclosure.
