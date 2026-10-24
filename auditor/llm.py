"""Talking to the LLM.

The agent loop only knows one tiny interface: ``client.chat(system, messages,
tools) -> LLMResponse``. Each provider class translates our neutral message
format to and from its own API. Only the official provider SDKs are used (no
agent frameworks).

Neutral message format:
    {"role": "user", "content": "text"}
    {"role": "assistant", "content": "text", "tool_calls": [ToolCall, ...]}
    {"role": "tool", "tool_call_id": "...", "name": "...", "content": "text"}
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field

log = logging.getLogger("auditor")


class LLMError(Exception):
    """A fatal LLM problem (bad key, unknown model, retries exhausted)."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict
    parse_error: str | None = None
    extra: dict | None = None  # provider data that must be echoed back (e.g. Gemini thought signatures)
    model: str | None = None  # model that produced this call


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=dict)


def _parse_args(raw) -> tuple[dict, str | None]:
    if isinstance(raw, dict):
        return raw, None
    if not raw:
        return {}, None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"arguments were not valid JSON: {exc}"
    return (value, None) if isinstance(value, dict) else ({}, "arguments must be a JSON object")


def _status(exc: Exception) -> int | None:
    return getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)


class _RetryingClient:
    """Retries temporary failures and falls back to the next model when one runs out of daily quota."""

    max_retries = 6
    min_interval = float(os.environ.get("LLM_REQUEST_DELAY", "0") or 0)

    def __init__(self, models: list[str]):
        self.models = [m for m in models if m]
        self._last_call = 0.0

    @property
    def model(self) -> str:
        return self.models[0]

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        delay = 2.0
        attempt = 0
        while True:
            attempt += 1
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            try:
                return self._chat(system, messages, tools)
            except LLMError:
                raise
            except Exception as exc:  # noqa: BLE001 - classify provider errors below
                status = _status(exc)
                if status == 429 and _is_daily_quota(exc):
                    if len(self.models) > 1:
                        log.warning("Daily quota used up for %s; switching to %s", self.models[0], self.models[1])
                        self.models.pop(0)
                        attempt, delay = 0, 2.0
                        continue
                    raise LLMError(
                        f"Daily request quota used up for {self.model}. Try again tomorrow, set LLM_MODEL to another model, or use another key: {_short(exc)}"
                    ) from exc
                if status in (400, 401, 403, 404, 422):
                    raise LLMError(f"LLM request rejected ({status}): {_short(exc)}") from exc
                if attempt >= self.max_retries:
                    raise LLMError(f"LLM request failed after {attempt} attempts: {_short(exc)}") from exc
                hint = _retry_hint(exc)
                time.sleep(min(hint, 90) if hint else delay + random.uniform(0, 1))
                delay = min(delay * 2, 60)

    def _chat(self, system, messages, tools) -> LLMResponse:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError


def _is_daily_quota(exc: Exception) -> bool:
    text = str(exc)
    return "PerDay" in text or "per day" in text.lower()


def _retry_hint(exc: Exception) -> float | None:
    match = re.search(r"retry in ([\d.]+)s", str(exc))
    return float(match.group(1)) + 1 if match else None


def _short(exc: Exception) -> str:
    text = str(exc).replace("\n", " ")
    return text[:300]


class OpenAIClient(_RetryingClient):
    """OpenAI, or any OpenAI-compatible API (Google Gemini, Groq, OpenRouter, Ollama, ...)."""

    def __init__(self, model: str | list[str], api_key: str | None, base_url: str | None = None, timeout: float = 120):
        super().__init__([model] if isinstance(model, str) else model)
        try:
            import openai
        except ImportError as exc:  # pragma: no cover
            raise LLMError("the 'openai' package is not installed: pip install -r requirements.txt") from exc
        self.client = openai.OpenAI(api_key=api_key or "not-needed", base_url=base_url or None, timeout=timeout, max_retries=0)

    def _chat(self, system, messages, tools) -> LLMResponse:
        wire = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant":
                msg = {"role": "assistant", "content": m.get("content") or None}
                if m.get("tool_calls"):
                    msg["tool_calls"] = []
                    for c in m["tool_calls"]:
                        wire_call = {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                        if c.extra and c.model == self.model:
                            wire_call["extra_content"] = c.extra
                        elif c.extra:
                            # Signature came from a different model (after a quota fallback); Gemini accepts this marker instead.
                            wire_call["extra_content"] = {"google": {"thought_signature": "skip_thought_signature_validator"}}
                        msg["tool_calls"].append(wire_call)
                wire.append(msg)
            elif m["role"] == "tool":
                wire.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                wire.append({"role": "user", "content": m["content"]})
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=wire,
            tools=[{"type": "function", "function": t} for t in tools],
            tool_choice="auto",
            temperature=0,
        )
        if not resp.choices:
            raise RuntimeError("empty response from LLM")
        msg = resp.choices[0].message
        calls = []
        for c in msg.tool_calls or []:
            args, err = _parse_args(c.function.arguments)
            extra = (getattr(c, "model_extra", None) or {}).get("extra_content")
            calls.append(
                ToolCall(
                    id=c.id or f"call_{uuid.uuid4().hex[:8]}",
                    name=c.function.name,
                    arguments=args,
                    parse_error=err,
                    extra=extra,
                    model=self.model,
                )
            )
        usage = (
            {"input": getattr(resp.usage, "prompt_tokens", 0), "output": getattr(resp.usage, "completion_tokens", 0)} if resp.usage else {}
        )
        return LLMResponse(text=msg.content or "", tool_calls=calls, usage=usage)


class AnthropicClient(_RetryingClient):
    """Anthropic Claude via the official SDK."""

    def __init__(self, model: str | list[str], api_key: str | None, timeout: float = 120):
        super().__init__([model] if isinstance(model, str) else model)
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise LLMError("the 'anthropic' package is not installed: pip install -r requirements.txt") from exc
        self.client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0)

    def _chat(self, system, messages, tools) -> LLMResponse:
        wire: list[dict] = []

        def push(role, blocks):
            if wire and wire[-1]["role"] == role:
                wire[-1]["content"].extend(blocks)
            else:
                wire.append({"role": role, "content": list(blocks)})

        for m in messages:
            if m["role"] == "assistant":
                blocks = [{"type": "text", "text": m["content"]}] if m.get("content") else []
                blocks += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments} for c in m.get("tool_calls") or []]
                push("assistant", blocks or [{"type": "text", "text": "(no content)"}])
            elif m["role"] == "tool":
                push("user", [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}])
            else:
                push("user", [{"type": "text", "text": m["content"]}])
        resp = self.client.messages.create(
            model=self.model,
            system=system,
            messages=wire,
            tools=[{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools],
            max_tokens=4096,
        )
        text, calls = [], []
        for block in resp.content:
            if block.type == "text":
                text.append(block.text)
            elif block.type == "tool_use":
                calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=block.input if isinstance(block.input, dict) else {}, model=self.model)
                )
        usage = {"input": resp.usage.input_tokens, "output": resp.usage.output_tokens}
        return LLMResponse(text="\n".join(text), tool_calls=calls, usage=usage)


DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-5-5",
    "gemini": "gemini-3.6-flash,gemini-3.5-flash-lite,gemini-3.1-flash-lite",
    "groq": "llama-3.3-70b-versatile",
}
COMPAT_BASE_URLS = {
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq": "https://api.groq.com/openai/v1",
}


def client_from_env() -> _RetryingClient:
    """Build the LLM client from environment variables (see .env.example)."""
    provider = (os.environ.get("LLM_PROVIDER") or "").strip().lower()
    if not provider:
        if os.environ.get("GEMINI_API_KEY"):
            provider = "gemini"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("GROQ_API_KEY"):
            provider = "groq"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            raise LLMError("No LLM credentials found. Copy .env.example to .env and set one API key (see README).")
    model_setting = os.environ.get("LLM_MODEL") or DEFAULT_MODELS.get(provider) or ""
    # LLM_MODEL may list several models, comma-separated: later ones are used when a model's daily quota runs out.
    model = [m.strip() for m in model_setting.split(",") if m.strip()]
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set")
        return AnthropicClient(model, key)
    if provider in ("gemini", "groq"):
        key = os.environ.get(f"{provider.upper()}_API_KEY")
        if not key:
            raise LLMError(f"LLM_PROVIDER={provider} but {provider.upper()}_API_KEY is not set")
        return OpenAIClient(model, key, os.environ.get("OPENAI_BASE_URL") or COMPAT_BASE_URLS[provider])
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("OPENAI_BASE_URL")
        if not key and not base_url:
            raise LLMError("LLM_PROVIDER=openai but OPENAI_API_KEY is not set")
        if not model:
            raise LLMError("Set LLM_MODEL")
        return OpenAIClient(model, key, base_url)
    raise LLMError(f"Unknown LLM_PROVIDER {provider!r}. Use gemini, openai, anthropic or groq.")
