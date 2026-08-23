"""OpenAI-compatible LLM client. Works with any endpoint that speaks the
/v1/chat/completions schema: local (ollama/vLLM/LM Studio) or cloud."""
from __future__ import annotations

import json
import re

from openai import OpenAI


DEFAULT_MODEL = "qwen3.8:27b"


class LLMError(Exception):
    pass


def extract_json(text: str):
    """Robust JSON extraction: fenced blocks, first {...} / [...]."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.S)
    if m:
        text = m.group(1)
    else:
        for opener, closer in (("{", "}"), ("[", "]")):
            i = text.find(opener)
            if i == -1:
                continue
            depth = 0
            for j in range(i, len(text)):
                if text[j] == opener:
                    depth += 1
                elif text[j] == closer:
                    depth -= 1
                    if depth == 0:
                        text = text[i : j + 1]
                        break
            else:
                continue
            break
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMError(f"model returned non-JSON: {e}") from e


class LLM:
    def __init__(self, base_url: str, api_key: str, model: str = DEFAULT_MODEL,
                 temperature: float = 0.1, timeout: float = 300.0):
        self.model = model
        self.client = OpenAI(base_url=base_url.rstrip("/"), api_key=api_key or "not-needed",
                             timeout=timeout, max_retries=1)

    def ping(self) -> list[str]:
        try:
            return sorted(m.id for m in self.client.models.list().data)
        except Exception as e:
            raise LLMError(str(e)) from e

    def ask(self, system: str, user: str, json_mode: bool = True, max_tokens: int = 4096) -> str:
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=0.1 if json_mode else 0.5,
                max_tokens=max_tokens,
                response_format={"type": "json_object"} if json_mode else None,
                extra_body={"chat_template_kwargs": {"enable_thinking": False}},
            )
        except Exception as e:
            raise LLMError(str(e)) from e
        content = resp.choices[0].message.content or ""
        if not content.strip():
            raise LLMError("empty completion")
        return content

    def ask_json(self, system: str, user: str, max_tokens: int = 4096):
        content = self.ask(system, user, json_mode=True, max_tokens=max_tokens)
        return extract_json(content)
