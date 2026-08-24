from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from ..config import LLMConfig, RunConfig, _default_api_key
from ..conductor import Conductor
from ..events import EventBus
from ..llm import LLM

STATE_FILE = Path.home() / ".config" / "deep-diver" / "state.json"
TOKEN_FILE = Path.home() / ".config" / "deep-diver" / "token"

app = FastAPI(title="deep-diver")
bus = EventBus()
STATIC = Path(__file__).parent / "static"


def _token() -> str:
    """Auth token from DEEPDIVER_TOKEN env or ~/.config/deep-diver/token.
    Empty = auth disabled (only safe when bound to loopback)."""
    t = os.getenv("DEEPDIVER_TOKEN", "")
    if not t:
        try:
            t = TOKEN_FILE.read_text().strip()
        except Exception:
            pass
    return t


def _authorized(request: Request) -> bool:
    t = _token()
    if not t:
        return True
    if request.headers.get("x-dv-token", "") == t:
        return True
    return request.query_params.get("token", "") == t


@app.middleware("http")
async def require_token(request: Request, call_next):
    if request.url.path.startswith("/api/") and not _authorized(request):
        return JSONResponse({"error": "bad or missing token (X-DV-Token)"}, status_code=401)
    return await call_next(request)


class Runtime:
    def __init__(self):
        self.conductor: Conductor | None = None
        self.task: asyncio.Task | None = None


rt = Runtime()


class StartBody(BaseModel):
    target: str
    scope: str = ""
    base_url: str = "http://localhost:8888/v1"
    api_key: str = Field(default_factory=_default_api_key)
    model: str = "ornith-ai/Ornith-1.5-35B-A3B-GGUF"
    mode: str = "aggressive"
    budget_minutes: int = 60
    max_steps: int = 400
    browser: bool = True
    recon_only: bool = False
    cred_email: str = ""
    cred_password: str = ""


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def save_state(d: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(d, indent=1))


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC / "index.html").read_text()


@app.get("/api/events")
async def events(request: Request):
    q = bus.subscribe()

    async def gen():
        try:
            for ev in list(bus.ring[-200:]):
                yield {"data": ev.to_json()}
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                    yield {"data": ev.to_json()}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": ""}
        finally:
            bus.unsubscribe(q)

    return EventSourceResponse(gen())


@app.get("/api/state")
async def state():
    running = rt.task is not None and not rt.task.done()
    cfg = rt.conductor.cfg if rt.conductor else None
    return {
        "running": running,
        "finished": rt.conductor.finished.is_set() if rt.conductor else False,
        "steps": rt.conductor.steps if rt.conductor else {"used": 0, "max": 0},
        "report": rt.conductor.report_path if rt.conductor else None,
        "scope": cfg.scope if cfg else "",
        "target": cfg.target if cfg else None,
        "findings": [f.to_dict() for f in rt.conductor.findings.all()[-100:]] if rt.conductor else [],
        "saved": load_state(),
    }


@app.post("/api/start")
async def start(body: StartBody):
    running = rt.task is not None and not rt.task.done()
    if running:
        return JSONResponse({"error": "already running"}, status_code=409)
    save_state({"base_url": body.base_url, "model": body.model,
                "scope": body.scope, "target": body.target})
    cfg = RunConfig(
        target=body.target, scope=body.scope or body.target,
        llm=LLMConfig(base_url=body.base_url, api_key=body.api_key, model=body.model),
        mode=body.mode, budget_minutes=body.budget_minutes,
        max_steps=body.max_steps, browser=body.browser,
        recon_only=body.recon_only,
        credentials=({"email": body.cred_email, "password": body.cred_password}
                     if body.cred_email else {}),
        report_dir="runs",
    )
    rt.conductor = Conductor(cfg, bus, workdir="runs")
    rt.task = asyncio.create_task(rt.conductor.run())
    return {"ok": True, "run_id": rt.conductor.run_id}


@app.post("/api/stop")
async def stop():
    if rt.conductor and rt.task and not rt.task.done():
        rt.conductor.stop()
        return {"ok": True}
    return {"ok": False}


@app.post("/api/llm/ping")
async def llm_ping(body: StartBody):
    try:
        llm = LLM(body.base_url, body.api_key, body.model)
        models = await asyncio.to_thread(llm.ping)
        return {"ok": True, "models": models}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/report")
async def report():
    if rt.conductor and rt.conductor.report_path:
        return Response(Path(rt.conductor.report_path).read_text(), media_type="text/markdown")
    return JSONResponse({"error": "no report yet"}, status_code=404)


def serve(port: int = 8911, host: str = "0.0.0.0"):
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="warning")
