from __future__ import annotations

import argparse
import json
import os

from .config import LLMConfig, RunConfig

DEFAULT_BASE_URL = LLMConfig.base_url
DEFAULT_MODEL = LLMConfig.model


def main():
    p = argparse.ArgumentParser(
        prog="deepdiver",
        description="deep-diver — autonomous bug bounty hunting agent. "
                    "Recon → crawl → origin-unmask → attack → verify → report.")
    sub = p.add_subparsers(dest="cmd")

    serve = sub.add_parser("serve", help="launch web dashboard (self-service scanning)")
    serve.add_argument("--port", type=int, default=8911)
    serve.add_argument("--host", default="127.0.0.1",
                       help="bind address (default loopback; use 0.0.0.0 only with --token)")
    serve.add_argument("--token", default="",
                       help="require this token on all /api/* routes (X-DV-Token header or ?token=); "
                            "persist to ~/.config/deep-diver/token so watchdog restarts keep it")

    run = sub.add_parser("run", help="one-shot headless scan: deepdiver run <URL>")
    run.add_argument("target")
    run.add_argument("--scope", default="", help="comma/newline scope list (default: target)")
    run.add_argument("--base-url", default=DEFAULT_BASE_URL)
    run.add_argument("--api-key", default="not-needed")
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.add_argument("--mode", default="aggressive", choices=["quiet", "normal", "aggressive"])
    run.add_argument("--budget", type=int, default=60, help="minutes")
    run.add_argument("--max-steps", type=int, default=400)
    run.add_argument("--no-browser", action="store_true")
    run.add_argument("--recon-only", action="store_true",
                     help="enumeration only: recon + crawl, zero attack probes")
    run.add_argument("--cred-email", default="", help="test account email (authenticated testing)")
    run.add_argument("--cred-password", default="", help="test account password")

    args = p.parse_args()
    if args.cmd == "serve":
        from .dashboard.app import serve, TOKEN_FILE
        if args.token:
            TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_FILE.write_text(args.token.strip())
            TOKEN_FILE.chmod(0o600)
            print(f"dashboard token enabled ({TOKEN_FILE})")
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            import os
            if not (args.token or os.getenv("DEEPDIVER_TOKEN") or TOKEN_FILE.exists()):
                print(f"WARNING: binding {args.host} WITHOUT a token — anyone reachable can "
                      f"launch scans and read reports. Use --token.")
        print(f"deep-diver dashboard: http://{args.host}:{args.port}")
        print("open it, paste a URL, LAUNCH HUNT. reports land in ./runs/")
        serve(args.port, args.host)
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
                browser=not args.no_browser, recon_only=args.recon_only,
                credentials=({"email": args.cred_email, "password": args.cred_password}
                             if args.cred_email else {}))
            c = Conductor(cfg, bus)
            await c.run()
            print(f"\nreport: {os.path.abspath(c.report_path) if c.report_path else 'none'}")

        asyncio.run(go())
    else:
        p.print_help()


if __name__ == "__main__":
    main()
