from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass

from .agents import BaseAgent
from .agents.cartographer import Cartographer
from .agents.hunter import Hunter
from .agents.scout import Scout
from .agents.verify import Auditor, Verifier
from .config import RunConfig
from .events import EventBus
from .llm import LLM, LLMError
from .models import FindingStore
from .scope import ScopeGuard
from .state import AttackSurface
from .tools import RateGovernor, Toolkit


CONDUCTOR_SYSTEM = """You are Conductor of an autonomous bug bounty agent. You plan the next move.
You have these agents:
- scout: subdomain/port/tech recon (action: {"agent":"scout","plan":{"target":"..."}})
- cartographer: crawl hosts, map urls/params/js/forms ({"agent":"cartographer","plan":{"hosts":[...]}})
- hunter: attack actions, each step is {"action":NAME,"args":{...}}; NAME is one of:
    nuclei_scan (args: tags,severity,urls), takeover_check, sensitive_files,
    test_sqli (args: max_urls), test_xss (max_urls), test_open_redirect (max_urls),
    test_ssrf (max_urls), test_path_traversal (max_urls), http_method_fuzz (max_urls), admin_probe
- verifier: confirm/reject candidates
- auditor: score + report

Given the current attack surface, budget, and findings, respond JSON ONLY:
{"agent": NAME, "plan": {...}, "why": "one sentence"}
Rules:
- Recon before crawling; crawling before hunting; verify candidates before finishing.
- Do not repeat actions already explored (check explored_actions).
- Prefer actions matching what the surface suggests (param names hint at bug class).
- Never act outside scope or target out-of-scope hosts.
- If enough data has been gathered, command DONE: {"agent":"done","plan":{},"why":"..."}
"""


class Conductor:
    def __init__(self, cfg: RunConfig, bus: EventBus, workdir: str = "runs"):
        self.cfg = cfg
        self.bus = bus
        self.workdir = workdir
        self.guard = ScopeGuard()
        gov_rps, _ = cfg.rate
        self.gov = RateGovernor(gov_rps)
        self.tk = Toolkit(self.guard, self.gov, workdir=workdir, browser=cfg.browser)
        self.surface = AttackSurface()
        self.findings = FindingStore()
        self.steps = {"used": 0, "max": int(cfg.max_steps)}
        self.llm = LLM(cfg.llm.base_url, cfg.llm.api_key, cfg.llm.model)
        self.scout = Scout(self.tk, self.surface, bus, self.findings, self.steps)
        self.cart = Cartographer(self.tk, self.surface, bus, self.findings, self.steps)
        self.hunter = Hunter(self.tk, self.surface, bus, self.findings, self.steps)
        self.verifier = Verifier(self.tk, self.surface, bus, self.findings, self.steps)
        self.auditor = Auditor(self.tk, self.surface, bus, self.findings, self.steps)
        self.agents = {a.name: a for a in
                       (self.scout, self.cart, self.hunter, self.verifier, self.auditor)}
        self.kill = asyncio.Event()
        self.finished = asyncio.Event()
        self.history: list[dict] = []
        self.run_id = time.strftime("%Y%m%d-%H%M%S")
        self.report_path = ""

    def stop(self):
        self.kill.set()

    async def run(self):
        t0 = time.time()
        deadline = t0 + self.cfg.budget_minutes * 60
        scope_text = self.cfg.scope or self.cfg.target
        self.guard.configure(scope_text)
        await self.bus.publish("phase", "conductor",
                               f"run {self.run_id} starting: target={self.cfg.target} "
                               f"mode={self.cfg.mode} budget={self.cfg.budget_minutes}m")
        await self.bus.publish("status", "conductor",
                               f"scope allowlist domains={sorted(self.guard.domains)} hosts={sorted(self.guard.hosts)} private={self.guard.allow_private}")
        try:
            # phase 1: deterministic scout pass, because llm may be flaky early
            await self.scout.run({"target": self.cfg.target})
            await self.cart.run({"hosts": sorted(self.surface.hosts)[:5]})
            while not self.kill.is_set() and time.time() < deadline and self.steps["used"] < self.steps["max"]:
                move = await self._next_move()
                if move is None:
                    break
                if move.get("agent") == "done":
                    break
                agent = self.agents.get(move.get("agent", ""))
                if not agent:
                    await self.bus.publish("error", "conductor", f"unknown agent in plan: {move}")
                    continue
                self.history.append(move)
                plan = move.get("plan", {})
                await self.bus.publish("phase", "conductor",
                                       f"-> {agent.name}: {move.get('why', '')[:100]}")
                summaries = await agent.run(plan)
                for s in summaries or []:
                    await self.bus.publish("log", agent.name, s)
                if move["agent"] == "verifier":
                    await self.auditor.run({})
            # final pass: verify + report
            await self.verifier.run({})
            await self.auditor.run({})
            self.report_path = await self.write_report()
            await self.bus.publish("status", "conductor",
                                   f"run complete: {len(self.findings.confirmed())} confirmed findings, "
                                   f"{self.steps['used']:.0f} steps used, report={self.report_path}")
            self.findings.items.sort(key=lambda f: -f.cvss)
        except Exception as e:
            await self.bus.publish("error", "conductor", f"run crashed: {type(e).__name__}: {e}")
            import traceback; traceback.print_exc()
        finally:
            await self.tk.close()
            self.finished.set()

    async def _next_move(self) -> dict | None:
        ctx = {
            "target": self.cfg.target,
            "steps_used": int(self.steps["used"]), "steps_max": self.steps["max"],
            "hosts": sorted(self.surface.hosts)[:20],
            "titles": {k: v[:60] for k, v in list(self.surface.titles.items())[:15]},
            "tech": dict(list(self.surface.tech.items())[:15]),
            "urls_count": len(self.surface.urls),
            "urls_with_params": len([u for u in self.surface.urls if "?" in u]),
            "js_endpoints": sorted(self.surface.js_endpoints)[:20],
            "forms": self.surface.forms[:10],
            "explored": sorted(self.surface.explored_actions)[-15:],
            "findings": [(f.status, f.severity, f.category, f.title, f.endpoint)
                         for f in self.findings.all()[-20:]],
            "candidates": sum(1 for f in self.findings.all() if f.status == "candidate"),
            "confirmed": sum(1 for f in self.findings.all() if f.status == "confirmed"),
        }
        surf = self.surface.summary()
        prompt = (
            f"Attack surface state:\n{surf}\n\n"
            f"Summary: {json.dumps(ctx)[:3000]}\n\n"
            f"History of plans so far ({len(self.history)}):\n"
            + "\n".join(json.dumps(h)[:140] for h in self.history[-12:])
            + "\n\nWhat is the next single best move? Reply JSON only."
        )
        for attempt in range(3):
            try:
                move = await asyncio.to_thread(self.llm.ask_json, CONDUCTOR_SYSTEM, prompt)
                if not isinstance(move, dict) or "agent" not in move:
                    raise LLMError(f"bad plan shape: {str(move)[:200]}")
                return move
            except LLMError as e:
                await self.bus.publish("error", "conductor", f"planning retry {attempt+1}: {e}")
                await asyncio.sleep(2)
            except Exception as e:
                await self.bus.publish("error", "conductor", f"planning error: {e}")
                await asyncio.sleep(2)
        # deterministic fallback: cycle hunt/verify based on state
        return self._fallback_move()

    def _fallback_move(self) -> dict:
        if self.findings.confirmed() or all(
                f.status != "candidate" for f in self.findings.all()):
            if self.steps["used"] > 3 and self.findings.confirmed():
                return {"agent": "done", "plan": {}, "why": "fallback: nothing more to do"}
        candidates = [f for f in self.findings.all() if f.status == "candidate"]
        if candidates and len(self.history) > 0 and self.history[-1].get("agent") != "verifier":
            return {"agent": "verifier", "plan": {}, "why": "fallback: verify candidates"}
        # else hunt by surface hints
        actions = []
        if not any(h.get("plan", {}).get("action") == "sensitive_files" for h in self.history):
            actions.append({"action": "sensitive_files", "args": {}})
        param_urls = [u for u in self.surface.urls if "?" in u]
        if param_urls:
            actions += [
                {"action": "test_sqli", "args": {"max_urls": 20}},
                {"action": "test_xss", "args": {"max_urls": 20}},
                {"action": "test_open_redirect", "args": {"max_urls": 10}},
                {"action": "test_path_traversal", "args": {"max_urls": 10}},
                {"action": "http_method_fuzz", "args": {"max_urls": 10}},
            ]
        if self.surface.hosts:
            actions.append({"action": "admin_probe", "args": {}})
            actions.append({"action": "takeover_check", "args": {}})
        if not actions:
            return {"agent": "done", "plan": {}, "why": "fallback: surface empty"}
        for i, a in enumerate(actions):
            sig = f"hunter:{a['action']}"
            if not any(h.get("agent") == "hunter" and
                       (h.get("plan", {}).get("actions") or [{}])[0].get("action") == a["action"]
                       for h in self.history):
                return {"agent": "hunter", "plan": {"actions": [a]}, "why": f"fallback: {a['action']}"}
        return {"agent": "done", "plan": {}, "why": "fallback: actions exhausted"}

    async def write_report(self) -> str:
        os.makedirs(self.workdir, exist_ok=True)
        path = f"{self.workdir}/report-{self.run_id}.md"
        confirmed = self.findings.confirmed()
        confirmed.sort(key=lambda f: -f.cvss)
        cands = [f for f in self.findings.all() if f.status == "candidate"]
        lines = [
            f"# deep-diver security report",
            f"",
            f"- target: `{self.cfg.target}`",
            f"- run: `{self.run_id}`",
            f"- time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- mode: {self.cfg.mode} | steps: {int(self.steps['used'])}/{self.steps['max']}",
            f"- live hosts: {len(self.surface.hosts)} | urls: {len(self.surface.urls)}",
            f"- findings: **{len(confirmed)} confirmed**, {len(cands)} candidates",
            "",
            "## Confirmed findings",
            "",
        ]
        if not confirmed:
            lines.append("_None confirmed._")
        for i, f in enumerate(confirmed, 1):
            lines += [
                f"### {i}. {f.title}",
                f"",
                f"- **Severity:** {f.severity.upper()} (CVSS {f.cvss})",
                f"- **Category:** {f.category}",
                f"- **Endpoint:** `{f.endpoint}`",
                f"- **Found by:** {f.agent}",
                f"- **Impact:** {f.impact or 'n/a'}",
                f"- **Bounty report ready:** {'yes' if f.bounty_ready else 'needs manual polish'}",
                "",
                "**Repro:**",
                "```",
                f.repro or f"curl -g '{f.endpoint}'",
                "```",
                "**Evidence:**",
                "```",
                (f.evidence or "")[:2000],
                "```",
                "",
            ]
        lines += ["## Unverified candidates", ""]
        if not cands:
            lines.append("_None._")
        for f in cands[:30]:
            lines.append(f"- ({f.severity}) {f.title} @ `{f.endpoint}`")
        lines += ["", "## Attack surface summary", "", "```", self.surface.summary(30)[:3000], "```",
                  "", "---",
                  "_Generated by deep-diver. All tests were rate-limited and non-destructive; "
                  "confirmations use safe detection payloads only._"]
        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        return path
