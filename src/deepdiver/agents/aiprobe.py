from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from . import BaseAgent


class AiProbe(BaseAgent):
    """garak-style reframed for SAFETY: identifies live AI endpoints and validates
    their exposure with benign marker prompts only. Detects:
      - echo/reflection of the prompt (information about internal handling)
      - model/info disclosure (model name, token counts, deployment)
      - obviously unauthenticated access to inference (cost/abuse vector)
    No prompt-injection payloads that could alter model behavior are sent.
    """
    name = "aiprobe"

    MARKER_PROMPT = ("Reply with exactly this token and nothing else: DV42AIAlive")

    async def run(self, plan: dict) -> list[str]:
        endpoints = self._ai_urls()
        out = []
        for url in sorted(endpoints)[:12]:
            if self.steps["used"] >= self.steps["max"]:
                break
            res = await self._probe(url)
            if res:
                out.append(res)
        return out or ["no AI endpoints probed"]

    def _ai_urls(self) -> set[str]:
        urls: set[str] = set()
        pat = re.compile(r"/(v1/(models|chat|completions|embeddings)|api/tags|api/chat|"
                         r"api/generate|gradio|api/openai|v1/chat/completions|mcp|llm)\b", re.I)
        for u in list(self.surf.urls) + list(self.surf.js_endpoints):
            if pat.search(urlparse(u).path):
                urls.add(u.split("?")[0])
        for host in self.surf.hosts:
            for path in ("/v1/models", "/api/tags"):
                urls.add(host.rstrip("/") + path)
        return urls

    async def _probe(self, url: str) -> str | None:
        path = urlparse(url).path.lower()
        if path.rstrip("/").endswith("/models") or path.rstrip("/").endswith("/api/tags"):
            return await self._list_models(url)
        # bodies for chat/completions style endpoints
        bodies = [
            ("application/json",
             json.dumps({"model": "default", "messages": [{"role": "user", "content": self.MARKER_PROMPT}],
                         "max_tokens": 40, "temperature": 0})),
            ("application/json",
             json.dumps({"model": "default", "prompt": self.MARKER_PROMPT, "max_tokens": 40})),
        ]
        for ct, body in bodies:
            r = await self.tk.fetch(url, method="POST", headers={"Content-Type": ct},
                                    data=body, max_bytes=8000)
            self.step(0.3)
            status = r.meta.get("status", 0)
            out = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
            low = out.lower()[:2000]
            if status == 200 and ("dv42aialive" in low or '"content"' in low or '"response"' in low):
                leaked = self._info_leak(low)
                await self.record(
                    title=f"AI inference endpoint reachable at {urlparse(url).netloc}{urlparse(url).path}",
                    severity="medium", category="ai-exposure", endpoint=url,
                    evidence=out[:800] + (f"\n{leaked}" if leaked else ""),
                    impact="Unauthenticated inference endpoint — cost abuse, data channel; "
                           + ("model/info disclosure detected" if leaked else ""),
                    cvss=5.6, status="confirmed", bounty_ready=False)
                return f"ai-probe: LIVE inference at {urlparse(url).netloc}{' +info-leak' if leaked else ''}"
            if status in (401, 403):
                return None
        return None

    async def _list_models(self, url: str) -> str | None:
        r = await self.tk.fetch(url, max_bytes=8000)
        self.step(0.2)
        if not r.ok or r.meta.get("status") != 200:
            return None
        out = r.output.split("\n\n", 1)[1] if "\n\n" in r.output else r.output
        low = out.lower()[:3000]
        if '"data"' not in low and '"models"' not in low:
            return None
        names = re.findall(r'"id"\s*:\s*"([^"]{3,60})"', out) or \
                re.findall(r'"name"\s*:\s*"([^"]{3,60})"', out)
        await self.record(
            title=f"AI model list exposed at {urlparse(url).netloc}{urlparse(url).path}",
            severity="medium", category="ai-exposure", endpoint=url,
            evidence=out[:1200],
            impact="Enumerates deployed models without authentication",
            cvss=5.3, status="confirmed")
        return f"ai-probe: model list at {urlparse(url).netloc}: {names[:4]}"

    def _info_leak(self, text: str) -> str:
        hits = []
        for m in re.finditer(r"(model|tokenizer|embedding|gpu|vram|temperature|max_tokens)\s*[:=]\s*[^,\}\s]{2,40}", text, re.I):
            hits.append(m.group(0))
        return "; ".join(dict.fromkeys(hits))[:300]
