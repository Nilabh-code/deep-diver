from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass

from .agents import BaseAgent
from .agents.aiprobe import AiProbe
from .agents.apiscan import ApiScanner
from .agents.authprobe import AuthProbe
from .agents.cartographer import Cartographer
from .agents.cvemap import CveMatcher
from .agents.hunter import Hunter
from .agents.origin import OriginHunter
from .agents.scout import Scout
from .agents.verify import Auditor, Verifier
from .config import RunConfig
from .events import EventBus
from .llm import LLM, LLMError
from .models import FindingStore
from .scope import ScopeGuard, ScopeViolation
from .state import AttackSurface
from .tools import RateGovernor, Toolkit


CONDUCTOR_SYSTEM = """You are Conductor of an autonomous bug bounty agent. You plan the next move.
You have these agents:
- scout: subdomain/port/tech recon (action: {"agent":"scout","plan":{"target":"..."}})
- origin: unmask origin IP behind CDN/WAF/load-balancers via cert transparency +
  DNS + curl --resolve fingerprint verification ({"agent":"origin","plan":{"apex":"domain.tld"}})
- apiscan: extract API routes from JS bundles, Next.js buildManifest, GraphQL
  introspection, well-known/openapi discovery ({"agent":"apiscan","plan":{"hosts":[...]}})
- cartographer: crawl hosts, map urls/params/js/forms ({"agent":"cartographer","plan":{"hosts":[...]}})
- hunter: attack actions, each step is {"action":NAME,"args":{...}}; NAME is one of:
    nuclei_scan (args: tags,severity,urls), takeover_check, sensitive_files,
    test_sqli (args: max_urls), test_xss (max_urls), test_open_redirect (max_urls),
    test_ssrf (max_urls), test_path_traversal (max_urls), http_method_fuzz (max_urls),
    admin_probe, path_brute (max_hosts), js_secrets, api_probe (max_urls),
    headers_cors (max_hosts), test_cmdi (max_urls), downgrade_check (max_hosts),
    host_header (max_hosts), user_enum (max_hosts)
- verifier: confirm/reject candidates
- auditor: score + report

Given the current attack surface, budget, and findings, respond JSON ONLY with a BATCH of moves:
{"moves": [{"agent": NAME, "plan": {...}, "why": "one sentence"}, ...]}
You may return 1-6 moves; plan as many hunter actions as the surface justifies in one batch,
e.g. {"agent":"hunter","plan":{"actions":[{"action":"test_sqli","args":{"max_urls":20}},{"action":"sensitive_files","args":{}}]}}
Rules:
- Recon before crawling; crawling before hunting; verify candidates before finishing.
- On CDN/WAF-fronted targets (e.g. Azure/Cloudflare IP) run origin early to find the real server IP.
- On SPA/API stacks run apiscan to map endpoints the crawler cannot see.
- Do not repeat actions already explored (check explored_actions).
- Prefer actions matching what the surface suggests (param names hint at bug class).
- Never act outside scope or target out-of-scope hosts.
- If enough data has been gathered, command DONE: {"moves":[{"agent":"done","plan":{},"why":"..."}]}
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
        self.origin = OriginHunter(self.tk, self.surface, bus, self.findings, self.steps)
        self.apiscan = ApiScanner(self.tk, self.surface, bus, self.findings, self.steps)
        self.cvemap = CveMatcher(self.tk, self.surface, bus, self.findings, self.steps)
        self.aiprobe = AiProbe(self.tk, self.surface, bus, self.findings, self.steps)
        self.authprobe = AuthProbe(self.tk, self.surface, bus, self.findings, self.steps,
                                   credentials=cfg.credentials)
        self.hunter = Hunter(self.tk, self.surface, bus, self.findings, self.steps)
        self.verifier = Verifier(self.tk, self.surface, bus, self.findings, self.steps)
        self.auditor = Auditor(self.tk, self.surface, bus, self.findings, self.steps)
        self.agents = {a.name: a for a in
                       (self.scout, self.cart, self.origin, self.apiscan,
                        self.hunter, self.verifier, self.auditor)}
        self.kill = asyncio.Event()
        self.finished = asyncio.Event()
        self.history: list[dict] = []
        self.run_id = time.strftime("%Y%m%d-%H%M%S")
        self.report_path = ""

    def stop(self):
        self.kill.set()

    async def _safe(self, agent, plan: dict, label: str) -> list[str]:
        """Run one recon agent; a failure degrades to an error event
        instead of killing the whole run."""
        try:
            return await agent.run(plan)
        except ScopeViolation as e:
            await self.bus.publish("error", "conductor",
                                   f"scope violation in {label} — skipped: {e}")
        except Exception as e:
            await self.bus.publish("error", "conductor",
                                   f"{label} failed: {type(e).__name__}: {e}")
        return []

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
            await self._safe(self.scout, {"target": self.cfg.target}, "scout")
            await self._safe(self.cart, {"hosts": sorted(self.surface.hosts)[:5]}, "cartographer")
            # always map APIs + try to unmask origin — cheap, high value, LLM-free
            await self._safe(self.apiscan, {"hosts": sorted(self.surface.hosts)[:3]}, "apiscan")
            apex = self.surface.root_target
            if apex.startswith("www."):
                apex = apex[4:]
            await self._safe(self.origin, {"apex": apex}, "origin")
            await self._safe(self.cvemap, {}, "cvemap")
            await self._safe(self.aiprobe, {}, "aiprobe")
            await self._safe(self.authprobe, {}, "authprobe")
            if self.cfg.recon_only:
                await self.bus.publish("status", "conductor",
                                       "recon_only mode: skipping all hunting/attack phases")
                self.report_path = await self.write_report()
                await self.bus.publish("status", "conductor",
                                       f"recon run complete, report={self.report_path}")
                return
            while not self.kill.is_set() and time.time() < deadline and self.steps["used"] < self.steps["max"]:
                moves = await self._next_round()
                if not moves or any(m.get("agent") == "done" for m in moves):
                    if moves and any(m.get("agent") == "done" for m in moves):
                        break
                    if not moves:
                        break
                for move in moves:
                    if self.kill.is_set() or time.time() >= deadline:
                        break
                    if move.get("agent") == "done":
                        continue
                    agent = self.agents.get(move.get("agent", ""))
                    if not agent:
                        await self.bus.publish("error", "conductor", f"unknown agent in plan: {move}")
                        continue
                    self.history.append(move)
                    plan = move.get("plan", {})
                    await self.bus.publish("phase", "conductor",
                                           f"-> {agent.name}: {move.get('why', '')[:100]}")
                    try:
                        summaries = await agent.run(plan)
                    except ScopeViolation as e:
                        await self.bus.publish("error", "conductor",
                                               f"scope violation in {agent.name} move — skipped: {e}")
                        continue
                    except Exception as e:
                        await self.bus.publish("error", "conductor",
                                               f"{agent.name} move failed: {type(e).__name__}: {e}")
                        continue
                    for s in summaries or []:
                        await self.bus.publish("log", agent.name, s)
                    if move["agent"] == "hunter":
                        await self.verifier.run({})
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
            try:
                self.report_path = await self.write_report()
                await self.bus.publish("status", "conductor",
                                       f"crashed but partial report saved: {self.report_path}")
            except Exception:
                pass
        finally:
            await self.tk.close()
            self.finished.set()

    async def _next_round(self) -> list[dict] | None:
        ctx = {
            "target": self.cfg.target,
            "steps_used": int(self.steps["used"]), "steps_max": self.steps["max"],
            "hosts": sorted(self.surface.hosts)[:15],
            "tech": dict(list(self.surface.tech.items())[:10]),
            "urls_count": len(self.surface.urls),
            "urls_with_params": len([u for u in self.surface.urls if "?" in u]),
            "param_urls_sample": [u for u in sorted(self.surface.urls) if "?" in u][:12],
            "js_endpoints": sorted(self.surface.js_endpoints)[:12],
            "explored": sorted(self.surface.explored_actions)[-12:],
            "findings": [(f.status, f.severity, f.category, f.title)
                         for f in self.findings.all()[-15:]],
            "candidates": sum(1 for f in self.findings.all() if f.status == "candidate"),
        }
        prompt = (
            f"Surface: {json.dumps(ctx)[:2600]}\n\n"
            f"History:\n" + "\n".join(json.dumps(h)[:120] for h in self.history[-8:])
            + "\n\nNext batch of moves? JSON only."
        )
        for attempt in range(2):
            try:
                await self.bus.publish("status", "conductor", f"planning batch {len(self.history)+1} (attempt {attempt+1})…")
                out = await asyncio.wait_for(
                    asyncio.to_thread(self.llm.ask_json, CONDUCTOR_SYSTEM, prompt, 800),
                    timeout=240)
                if isinstance(out, dict) and "agent" in out:
                    out = {"moves": [out]}
                moves = (out or {}).get("moves") if isinstance(out, dict) else None
                if not isinstance(moves, list) or not moves:
                    raise LLMError(f"bad batch shape: {str(out)[:200]}")
                return [m for m in moves if isinstance(m, dict) and "agent" in m][:6]
            except Exception as e:
                await self.bus.publish("error", "conductor",
                                       f"planning retry {attempt+1}: {type(e).__name__}: {str(e)[:150]}")
                await asyncio.sleep(1)
        await self.bus.publish("status", "conductor", "model unavailable — using deterministic hunt cycle")
        return [self._fallback_move()]

    def _hunted_actions(self) -> set[str]:
        done = set()
        for h in self.history:
            if h.get("agent") != "hunter":
                continue
            plan = h.get("plan", {})
            acts = plan.get("actions") or ([{"action": plan["action"]}] if plan.get("action") else [])
            for a in acts:
                if isinstance(a, dict) and a.get("action"):
                    done.add(a["action"])
        return done

    def _fallback_move(self) -> dict:
        params_ready = bool([u for u in self.surface.urls if "?" in u])
        if params_ready:
            plan_actions = [
                {"action": "sensitive_files", "args": {}},
                {"action": "headers_cors", "args": {"max_hosts": 10}},
                {"action": "api_probe", "args": {"max_urls": 30}},
                {"action": "test_sqli", "args": {"max_urls": 25}},
                {"action": "test_xss", "args": {"max_urls": 25}},
                {"action": "test_cmdi", "args": {"max_urls": 20}},
                {"action": "test_open_redirect", "args": {"max_urls": 15}},
                {"action": "test_path_traversal", "args": {"max_urls": 15}},
                {"action": "test_ssrf", "args": {"max_urls": 10}},
                {"action": "http_method_fuzz", "args": {"max_urls": 12}},
                {"action": "downgrade_check", "args": {"max_hosts": 8}},
                {"action": "host_header", "args": {"max_hosts": 8}},
                {"action": "user_enum", "args": {"max_hosts": 4}},
                {"action": "admin_probe", "args": {}},
            ]
        else:
            plan_actions = [
                {"action": "sensitive_files", "args": {}},
                {"action": "js_secrets", "args": {}},
                {"action": "path_brute", "args": {"max_hosts": 3}},
                {"action": "admin_probe", "args": {}},
                {"action": "nuclei_scan", "args": {"severity": "medium,high,critical"}},
            ]
        remaining = [a for a in plan_actions if a["action"] not in self._hunted_actions()]
        if remaining:
            return {"agent": "hunter", "plan": {"actions": remaining[:6]},
                    "why": "deterministic hunt cycle"}
        candidates = [f for f in self.findings.all() if f.status == "candidate"]
        if candidates and not any(h.get("agent") == "verifier" for h in self.history):
            return {"agent": "verifier", "plan": {}, "why": "verify candidates"}
        return {"agent": "done", "plan": {}, "why": "hunt cycle exhausted"}

    async def _executive_summary(self, confirmed: list, cands: list) -> str:
        facts = [f"{f.severity}|{f.category}|{f.title}|{f.endpoint}" for f in confirmed[:40]]
        prompt = (
            f"Target: {self.cfg.target}\n"
            f"Confirmed findings ({len(confirmed)}):\n" + "\n".join(facts) +
            f"\nCandidates: {len(cands)}\nHosts: {len(self.surface.hosts)}, "
            f"URLs: {len(self.surface.urls)}\n\n"
            "Write a 3-5 sentence security executive summary in plain markdown. "
            "Highlight the most exploitable issues first, note remediation priority."
        )
        try:
            text = await asyncio.wait_for(
                asyncio.to_thread(self.llm.ask,
                                  "You are a senior security engineer writing a pentest "
                                  "executive summary. Be concrete, no fluff, no JSON.",
                                  prompt, False, 700),
                timeout=180)
            return text.strip()
        except Exception:
            if not confirmed:
                return "_No confirmed findings in this run._"
            top = confirmed[0]
            return (f"Hunt confirmed {len(confirmed)} findings, highest: "
                    f"**{top.title}** ({top.severity}, CVSS {top.cvss}) at `{top.endpoint}`. "
                    f"API endpoints discovered: {len(self.surface.js_endpoints)}. "
                    f"Recommend prioritizing origin-disclosure and access-control items.")

    async def write_report(self) -> str:
        os.makedirs(self.workdir, exist_ok=True)
        path = f"{self.workdir}/report-{self.run_id}.md"
        confirmed = self.findings.confirmed()
        confirmed.sort(key=lambda f: -f.cvss)
        cands = [f for f in self.findings.all() if f.status == "candidate"]
        summary = await self._executive_summary(confirmed, cands)
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
            "## Executive summary",
            "",
            summary,
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
