from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


def _default_api_key() -> str:
    """LLM key comes from DEEPDIVER_LLM_KEY or ~/.config/deep-diver/key (chmod 600) —
    never hardcoded in source."""
    import os
    key = os.getenv("DEEPDIVER_LLM_KEY", "")
    if not key:
        try:
            key = (Path.home() / ".config" / "deep-diver" / "key").read_text().strip()
        except Exception:
            pass
    return key


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:8888/v1"
    api_key: str = field(default_factory=_default_api_key)
    model: str = "ornith-ai/Ornith-1.5-35B-A3B-GGUF"


@dataclass
class RunConfig:
    target: str = ""                     # starting URL/domain
    scope: str = ""                      # newline/comma list; !private for labs
    llm: LLMConfig = field(default_factory=LLMConfig)
    mode: str = "aggressive"             # quiet|normal|aggressive (rate governor still caps)
    budget_minutes: int = 60
    max_steps: int = 400
    browser: bool = True
    recon_only: bool = False
    credentials: dict = field(default_factory=dict)   # {"email": ..., "password": ...}
    report_dir: str = "runs"

    RATE = {"quiet": (1.0, 1.0), "normal": (4.0, 4.0), "aggressive": (12.0, 15.0)}
    # tuple (requests_per_second, concurrency)

    @property
    def rate(self) -> tuple[float, int]:
        return self.RATE.get(self.mode, self.RATE["normal"])
