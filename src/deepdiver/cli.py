from __future__ import annotations

import argparse
import json

from .config import LLMConfig, RunConfig


def main():
    p = argparse.ArgumentParser(prog="deepdiver", description="autonomous bug bounty hunting agent")
    sub = p.add_subparsers(dest="cmd")

    serve = sub.add_parser("serve", help="launch web dashboard")
    serve.add_argument("--port", type=int, default=8911)

    run = sub.add_parser("run", help="headless run on a target")
    run.add_argument("target")
    run.add_argument("--scope", default="", help="comma/newline scope list (default: target)")
    run.add_argument("--base-url", default="http://localhost:11434/v1")
    run.add_argument("--api-key", default="not-needed")
    run.add_argument("--model", default="qwen3-max")
    run.add_argument("--mode", default="aggressive", choices=["quiet", "normal", "aggressive"])
    run.add_argument("--budget", type=int, default=60, help="minutes")
    run.add_argument("--max-steps", type=int, default=400)
    run.add_argument("--no-browser", action="store_true")

    args = p.parse_args()
    if args.cmd == "serve":
        from .dashboard.app import serve
        print(f"deep-diver dashboard: http://localhost:{args.port}")
        serve(args.port)
    elif args.cmd == "run":
        import asyncio
        from .conductor import Conductor
        from .events import EventBus

        async def go():
            bus = EventBus()
            cfg = RunConfig(
                target=args.target, scope=args.scope or args.target,
                llm=LLMConfig(base_url=args.base_url, api_key=args.api_key, model=args.model),
                mode=args.mode, budget_minutes=args.budget, max_steps=args.max_steps,
                browser=not args.no_browser)
            c = Conductor(cfg, bus)
            await c.run()

        asyncio.run(go())
    else:
        p.print_help()


if __name__ == "__main__":
    main()
