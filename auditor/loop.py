"""The agent loop: Observe -> Reason -> Select tool -> Execute -> Interpret -> Report.

This file is the "brain stem" of the agent. It does not decide *what* to
inspect; the LLM does. The loop's job is to:
  1. send the conversation so far to the LLM,
  2. run whichever tools the LLM asked for (inspection or reporting tools),
  3. feed the results back, and
  4. enforce safety rails: step/time budgets, a coverage check and a
     self-review pass before the agent is allowed to finish.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from auditor.llm import LLMError, LLMResponse
from auditor.prompts import BUDGET_WARNING, CONTROL_TOOLS, SYSTEM_PROMPT, review_message, start_message
from auditor.redact import redact, redact_obj
from auditor.report import Findings
from auditor.rules import CATEGORIES

log = logging.getLogger("auditor")

HISTORY_CHAR_BUDGET = 160_000  # older tool outputs are trimmed beyond this
TRIMMED_TOOL_CHARS = 600


class Trace:
    """Records every LLM turn and tool call (JSON Lines) so the run can be audited."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self.events: list[dict] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    def add(self, **event) -> None:
        event = redact_obj({"t": round(time.time(), 3), **event})
        self.events.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")


class AuditAgent:
    def __init__(self, llm, tools, repo_summary: str, *, max_steps: int = 60, max_seconds: float = 900, trace: Trace | None = None):
        self.llm = llm
        self.tools = tools
        self.repo_summary = repo_summary
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.trace = trace or Trace(None)
        self.findings = Findings(tools)
        self.messages: list[dict] = []
        self.tool_schemas = tools.SCHEMAS + CONTROL_TOOLS
        self.reviewed = False
        self.budget_warned = False
        self.finished = False
        self.stop_reason = ""
        self.tool_calls = 0

    # ------------------------------------------------------------------ public
    def run(self) -> list[dict]:
        start = time.monotonic()
        self.messages.append({"role": "user", "content": start_message(self.repo_summary)})
        self.trace.add(type="start", repo=self.repo_summary)
        idle = 0
        for step in range(1, self.max_steps + 1):
            elapsed = time.monotonic() - start
            if elapsed > self.max_seconds:
                self.stop_reason = f"time budget of {self.max_seconds:.0f}s reached"
                break
            if not self.budget_warned and (step >= self.max_steps - 3 or elapsed > self.max_seconds * 0.85):
                self._append_user(BUDGET_WARNING)
                self.budget_warned = True
            self._trim_history()
            try:
                response: LLMResponse = self.llm.chat(SYSTEM_PROMPT, self.messages, self.tool_schemas)
            except LLMError as exc:
                self.stop_reason = f"LLM error: {exc}"
                self.trace.add(type="end", reason=self.stop_reason, tool_calls=self.tool_calls, violations=len(self.findings.active()))
                raise
            self.trace.add(
                type="llm",
                step=step,
                reasoning=response.text,
                tool_calls=[{"name": c.name, "args": c.arguments} for c in response.tool_calls],
                usage=response.usage,
            )
            if response.text.strip():
                log.info("[step %d] thinking: %s", step, response.text.strip().replace("\n", " ")[:200])
            self.messages.append({"role": "assistant", "content": response.text, "tool_calls": response.tool_calls})

            if not response.tool_calls:
                idle += 1
                if idle >= 3:
                    self.stop_reason = "model stopped calling tools"
                    break
                self._append_user("Continue the investigation with a tool call, or call finish if you are done.")
                continue
            idle = 0
            for call in response.tool_calls:
                result = self._execute(step, call)
                self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": result})
            if self.finished:
                self.stop_reason = "agent finished"
                break
        else:
            self.stop_reason = f"step budget of {self.max_steps} reached"
        self.trace.add(
            type="end",
            reason=self.stop_reason,
            tool_calls=self.tool_calls,
            violations=len(self.findings.active()),
            retracted=len(self.findings.retracted),
        )
        log.info("Stopped: %s. %d tool calls, %d violation(s).", self.stop_reason, self.tool_calls, len(self.findings.active()))
        return self.findings.active()

    # ---------------------------------------------------------------- internals
    def _execute(self, step: int, call) -> str:
        self.tool_calls += 1
        started = time.monotonic()
        if call.parse_error:
            result = f"ERROR: {call.parse_error}"
        elif call.name == "report_violation":
            result = self.findings.add(call.arguments)
        elif call.name == "retract_violation":
            result = self.findings.retract(call.arguments.get("id"), call.arguments.get("reason"))
        elif call.name == "finish":
            result = self._finish(call.arguments)
        else:
            result = self.tools.call(call.name, call.arguments)
        result = redact(result)
        log.info("[step %d] %s(%s) -> %s", step, call.name, _short_args(call.arguments), result.splitlines()[0][:120] if result else "")
        self.trace.add(
            type="tool", step=step, name=call.name, args=call.arguments, seconds=round(time.monotonic() - started, 2), output=result[:4000]
        )
        return result

    def _finish(self, args: dict) -> str:
        checked = args.get("categories_checked") or {}
        if not isinstance(checked, dict):
            checked = {}
        missing = [c for c in CATEGORIES if not str(checked.get(c, "")).strip()]
        if missing and not self.budget_warned:
            return (
                "NOT FINISHED: give a note for every category. Missing: "
                + ", ".join(missing)
                + ". If you have not investigated one of these yet and it applies to this repository, investigate it now."
            )
        if not self.reviewed and not self.budget_warned and self.findings.active():
            self.reviewed = True
            self.trace.add(type="note", message="self-review requested")
            return review_message(self.findings.summary())
        self.finished = True
        self.trace.add(type="finish", categories_checked=checked, summary=args.get("summary", ""))
        return "Finished."

    def _append_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def _trim_history(self) -> None:
        """Keep the conversation within budget by shortening the oldest tool outputs."""
        total = sum(len(m.get("content") or "") for m in self.messages)
        for m in self.messages:
            if total <= HISTORY_CHAR_BUDGET:
                break
            if m["role"] == "tool" and len(m["content"]) > TRIMMED_TOOL_CHARS and not m["content"].endswith("[older output trimmed]"):
                total -= len(m["content"]) - TRIMMED_TOOL_CHARS
                m["content"] = m["content"][:TRIMMED_TOOL_CHARS] + "\n[older output trimmed]"


def _short_args(args: dict) -> str:
    text = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items() if k not in ("evidence", "recommendation", "description"))
    return text[:120]
