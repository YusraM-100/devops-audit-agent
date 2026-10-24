"""Provider adapters, tested against a fake HTTP server (no network, no API key)."""

from __future__ import annotations

import json

import anthropic
import httpx2 as httpx
import openai
import pytest

from auditor.llm import AnthropicClient, LLMError, OpenAIClient

TOOLS = [{"name": "list_files", "description": "List files", "parameters": {"type": "object", "properties": {}}}]


def _mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_tool_calls_round_trip_with_gemini_signature():
    sent = []
    reply = {
        "id": "x",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "look",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "list_files", "arguments": "{}"},
                            "extra_content": {"google": {"thought_signature": "SIG"}},
                        }
                    ],
                },
            }
        ],
    }

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=reply)

    client = OpenAIClient("m", "k", "https://llm.invalid/v1")
    client.client = openai.OpenAI(api_key="k", base_url="https://llm.invalid/v1", http_client=_mock(handler), max_retries=0)
    first = client.chat("sys", [{"role": "user", "content": "go"}], TOOLS)
    assert first.text == "look" and first.tool_calls[0].name == "list_files"
    client.chat(
        "sys",
        [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": first.text, "tool_calls": first.tool_calls},
            {"role": "tool", "tool_call_id": "c1", "name": "list_files", "content": "a.py"},
        ],
        TOOLS,
    )
    msgs = sent[1]["messages"]
    assert msgs[0] == {"role": "system", "content": "sys"}
    assert msgs[2]["tool_calls"][0]["extra_content"] == {"google": {"thought_signature": "SIG"}}
    assert msgs[3] == {"role": "tool", "tool_call_id": "c1", "content": "a.py"}


def test_openai_auth_error_is_fatal_without_retry():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client = OpenAIClient("m", "k", "https://llm.invalid/v1")
    client.client = openai.OpenAI(api_key="k", base_url="https://llm.invalid/v1", http_client=_mock(handler), max_retries=0)
    with pytest.raises(LLMError, match="401"):
        client.chat("sys", [{"role": "user", "content": "go"}], TOOLS)
    assert len(calls) == 1


def test_server_errors_are_retried(monkeypatch):
    monkeypatch.setattr("auditor.llm.time.sleep", lambda s: None)
    calls = []
    ok = {
        "id": "x",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
    }

    def handler(request):
        calls.append(1)
        return httpx.Response(503, json={"error": {"message": "busy"}}) if len(calls) < 3 else httpx.Response(200, json=ok)

    client = OpenAIClient("m", "k", "https://llm.invalid/v1")
    client.client = openai.OpenAI(api_key="k", base_url="https://llm.invalid/v1", http_client=_mock(handler), max_retries=0)
    assert client.chat("sys", [{"role": "user", "content": "go"}], TOOLS).text == "hi"
    assert len(calls) == 3


def test_anthropic_merges_tool_results_into_one_user_turn():
    sent = []
    reply = {
        "id": "m",
        "type": "message",
        "role": "assistant",
        "model": "x",
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 1, "output_tokens": 1},
        "content": [{"type": "text", "text": "checking"}, {"type": "tool_use", "id": "t1", "name": "list_files", "input": {}}],
    }

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=reply)

    client = AnthropicClient("x", "k")
    client.client = anthropic.Anthropic(api_key="k", base_url="https://llm.invalid", http_client=_mock(handler), max_retries=0)
    first = client.chat("sys", [{"role": "user", "content": "go"}], TOOLS)
    assert first.tool_calls[0].id == "t1"
    client.chat(
        "sys",
        [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": first.text, "tool_calls": first.tool_calls},
            {"role": "tool", "tool_call_id": "t1", "name": "list_files", "content": "a.py"},
            {"role": "user", "content": "keep going"},
        ],
        TOOLS,
    )
    body = sent[1]
    assert body["system"] == "sys"
    assert body["tools"][0]["input_schema"] == TOOLS[0]["parameters"]
    assert [m["role"] for m in body["messages"]] == ["user", "assistant", "user"]
    assert body["messages"][2]["content"][0]["type"] == "tool_result"
    assert body["messages"][2]["content"][1] == {"type": "text", "text": "keep going"}


def test_daily_quota_switches_to_next_model_and_replaces_foreign_signature():
    sent = []
    quota = {
        "error": {"code": 429, "message": "Generate content requests per day limit exceeded on Free Tier", "status": "RESOURCE_EXHAUSTED"}
    }
    ok = {
        "id": "x",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
    }

    def handler(request):
        body = json.loads(request.content)
        sent.append(body)
        return httpx.Response(429, json=[quota]) if body["model"] == "big" else httpx.Response(200, json=ok)

    from auditor.llm import ToolCall

    client = OpenAIClient(["big", "small"], "k", "https://llm.invalid/v1")
    client.client = openai.OpenAI(api_key="k", base_url="https://llm.invalid/v1", http_client=_mock(handler), max_retries=0)
    old_call = ToolCall("c1", "list_files", {}, extra={"google": {"thought_signature": "SIG"}}, model="big")
    history = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [old_call]},
        {"role": "tool", "tool_call_id": "c1", "name": "list_files", "content": "a.py"},
    ]
    assert client.chat("sys", history, TOOLS).text == "hi"
    assert [b["model"] for b in sent] == ["big", "small"]
    assert sent[1]["messages"][2]["tool_calls"][0]["extra_content"]["google"]["thought_signature"] == "skip_thought_signature_validator"


def test_daily_quota_on_last_model_is_fatal():
    def handler(request):
        return httpx.Response(429, json=[{"error": {"code": 429, "message": "requests per day exceeded"}}])

    client = OpenAIClient(["only"], "k", "https://llm.invalid/v1")
    client.client = openai.OpenAI(api_key="k", base_url="https://llm.invalid/v1", http_client=_mock(handler), max_retries=0)
    with pytest.raises(LLMError, match="Daily request quota"):
        client.chat("sys", [{"role": "user", "content": "go"}], TOOLS)
