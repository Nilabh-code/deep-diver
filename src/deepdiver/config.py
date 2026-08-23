from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "not-needed"
    model: str = "qwen3-max"


@dataclass
class RunConfig:
    target: str = ""                     # starting URL/domain
    scope: str = ""                      # newline/comma list; !private for labs
    llm: LLMConfig = field(default_factory=LLMConfig)
    mode: str = "aggressive"             # quiet|normal|aggressive (rate governor still caps)
    budget_minutes: int = 60
    max_steps: int = 400
    browser: bool = True
    report_dir: str = "runs"

    RATE = {"quiet": (1.0, 1.0), "normal": (4.0, 4.0), "aggressive": (12.0, 15.0)}
    # tuple (requests_per_second, concurrency)

    @property
    def rate(self) -> tuple[float, int]:
        return self.RATE.get(self.mode, self.RATE["normal"])
