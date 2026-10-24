"""Agent-loop behaviour, using a scripted fake LLM (no network, no API key)."""

from __future__ import annotations

import json

from conftest import ALL_CATEGORIES_NOTE, FAKE_KEY, ScriptedLLM

import agent
from auditor.llm import LLMError, LLMResponse, ToolCall
from auditor.loop import AuditAgent, Trace
from tools import RepoTools

VIOLATION = {
    "rule_id": "SEC-001",
    "category": "security",
    "severity": "critical",
    "file": "app.py",
    "line": 3,
    "description": "Hardcoded AWS access key in source",
    "evidence": "AWS_KEY is assigned a literal access key id",
    "recommendation": "Read the key from an environment variable or secret manager",
}
FINISH = ("finish", {"categories_checked": ALL_CATEGORIES_NOTE, "summary": "done"})


def test_tool_results_are_fed_back_to_the_llm(bad_repo):
    llm = ScriptedLLM([[("list_files", {})], [("read_file", {"path": "app.py"})], [FINISH]])
    AuditAgent(llm, RepoTools(bad_repo), "repo").run()
    # The second LLM call must see the list_files output; the third must see the file contents.
    assert any(m["role"] == "tool" and "app.py" in m["content"] for m in llm.calls[1])
    assert any(m["role"] == "tool" and "AWS_KEY" in m["content"] for m in llm.calls[2])


def test_llm_chooses_follow_up_based_on_observation(bad_repo):
    """A dynamic policy: only read the workflow if list_files revealed one."""

    def decide(messages):
        last = messages[-1]["content"]
        if ".github/workflows/ci.yml" in last:
            return LLMResponse(text="CI exists, inspect it", tool_calls=[ToolCall("w", "inspect_workflows", {})])
        return LLMResponse(text="", tool_calls=[ToolCall("f", *FINISH)])

    llm = ScriptedLLM([[("list_files", {})], decide, [FINISH]])
    a = AuditAgent(llm, RepoTools(bad_repo), "repo")
    a.run()
    names = [c.name for m in a.messages if m["role"] == "assistant" for c in m["tool_calls"]]
    assert names[:2] == ["list_files", "inspect_workflows"]


def test_finish_requires_category_coverage_then_self_review(bad_repo):
    llm = ScriptedLLM(
        [
            [("report_violation", VIOLATION)],
            [("finish", {"categories_checked": {"security": "checked"}, "summary": "x"})],  # rejected: incomplete
            [FINISH],  # triggers self-review
            [FINISH],  # accepted
        ]
    )
    a = AuditAgent(llm, RepoTools(bad_repo), "repo")
    result = a.run()
    tool_outputs = [m["content"] for m in a.messages if m["role"] == "tool"]
    assert tool_outputs[1].startswith("NOT FINISHED")
    assert "review your findings" in tool_outputs[2]
    assert tool_outputs[3] == "Finished."
    assert len(result) == 1 and a.stop_reason == "agent finished"


def test_retraction_during_review_removes_false_positive(bad_repo):
    llm = ScriptedLLM([[("report_violation", VIOLATION)], [FINISH], [("retract_violation", {"id": "V1", "reason": "test"})], [FINISH]])
    assert AuditAgent(llm, RepoTools(bad_repo), "repo").run() == []


def test_step_budget_stops_runaway_agent(bad_repo):
    llm = ScriptedLLM([[("list_files", {})]] * 50)
    a = AuditAgent(llm, RepoTools(bad_repo), "repo", max_steps=5)
    a.run()
    assert "step budget" in a.stop_reason
    assert len(llm.calls) == 5


def test_bad_tool_arguments_do_not_crash(bad_repo):
    llm = ScriptedLLM([[("read_file", {"wrong": 1}), ("nonexistent_tool", {})], [FINISH]])
    a = AuditAgent(llm, RepoTools(bad_repo), "repo")
    a.run()
    outputs = [m["content"] for m in a.messages if m["role"] == "tool"]
    assert outputs[0].startswith("ERROR") and outputs[1].startswith("ERROR")


def test_trace_is_written_and_has_no_secrets(bad_repo, tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    llm = ScriptedLLM([[("read_file", {"path": "app.py"})], [FINISH]])
    AuditAgent(llm, RepoTools(bad_repo), "repo", trace=Trace(trace_path)).run()
    text = trace_path.read_text()
    events = [json.loads(line) for line in text.splitlines()]
    assert {e["type"] for e in events} >= {"start", "llm", "tool", "finish", "end"}
    assert FAKE_KEY not in text


# ----------------------------------------------------------------------- CLI
def test_cli_end_to_end_writes_valid_report(bad_repo, tmp_path):
    out = tmp_path / "report.json"
    llm = ScriptedLLM([[("list_files", {})], [("report_violation", VIOLATION)], [FINISH], [FINISH]])
    code = agent.main(["--repo", str(bad_repo), "--output", str(out), "-q"], llm=llm)
    assert code == 0
    report = json.loads(out.read_text())
    assert report["violations"][0]["rule_id"] == "SEC-001"
    assert FAKE_KEY not in out.read_text()
    assert (tmp_path / "report.trace.jsonl").exists()


def test_cli_empty_violations_still_writes_report(healthy_repo, tmp_path):
    out = tmp_path / "r.json"
    assert agent.main(["--repo", str(healthy_repo), "--output", str(out), "-q"], llm=ScriptedLLM([[FINISH]])) == 0
    assert json.loads(out.read_text())["violations"] == []


def test_cli_invalid_url_exits_nonzero(tmp_path, capsys):
    assert agent.main(["--repo", "not a url", "--output", str(tmp_path / "r.json")], llm=ScriptedLLM([])) == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_cli_llm_failure_exits_nonzero(bad_repo, tmp_path, capsys):
    class Broken:
        def chat(self, *a):
            raise LLMError("LLM request rejected (401): invalid key")

    assert agent.main(["--repo", str(bad_repo), "--output", str(tmp_path / "r.json")], llm=Broken()) == 1
    assert "401" in capsys.readouterr().err


def test_cli_does_not_modify_target(bad_repo, tmp_path):
    import subprocess

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=bad_repo, capture_output=True, text=True).stdout
    agent.main(["--repo", str(bad_repo), "--output", str(tmp_path / "r.json"), "-q"], llm=ScriptedLLM([[("git_status", {})], [FINISH]]))
    status = subprocess.run(["git", "status", "--porcelain"], cwd=bad_repo, capture_output=True, text=True).stdout
    assert status == "" and head == subprocess.run(["git", "rev-parse", "HEAD"], cwd=bad_repo, capture_output=True, text=True).stdout


def test_missing_credentials_message(monkeypatch):
    from auditor.llm import client_from_env

    for var in ["LLM_PROVIDER", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY"]:
        monkeypatch.delenv(var, raising=False)
    try:
        client_from_env()
    except LLMError as exc:
        assert ".env" in str(exc)
    else:
        raise AssertionError("expected LLMError")
