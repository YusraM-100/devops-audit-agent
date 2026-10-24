"""Tests for the inspection tools in tools.py."""

from __future__ import annotations

from conftest import FAKE_KEY

from tools import RepoTools


def test_list_files_shows_tracked_files(bad_repo):
    out = RepoTools(bad_repo).call("list_files", {})
    assert "app.py" in out
    assert "__pycache__/app.cpython-312.pyc" in out
    assert ".git/" not in out


def test_list_files_subdirectory(bad_repo):
    out = RepoTools(bad_repo).call("list_files", {"path": ".github"})
    assert ".github/workflows/ci.yml" in out
    assert "app.py" not in out


def test_read_file_numbers_lines_and_redacts(bad_repo):
    out = RepoTools(bad_repo).call("read_file", {"path": "app.py"})
    assert "    3| AWS_KEY = '[REDACTED]'" in out
    assert FAKE_KEY not in out


def test_read_file_range(bad_repo):
    out = RepoTools(bad_repo).call("read_file", {"path": "app.py", "start_line": 6, "end_line": 7})
    assert "    6| def main" in out and "    1|" not in out


def test_read_file_errors_are_returned_not_raised(bad_repo):
    tools = RepoTools(bad_repo)
    assert tools.call("read_file", {"path": "nope.py"}).startswith("ERROR")
    assert "outside the repository" in tools.call("read_file", {"path": "../../etc/passwd"})
    assert tools.call("read_file", {}).startswith("ERROR: bad arguments")
    assert tools.call("rm_rf", {}).startswith("ERROR: unknown tool")


def test_search_code_finds_pattern_with_location(bad_repo):
    out = RepoTools(bad_repo).call("search_code", {"pattern": r"verify\s*=\s*False"})
    assert "app.py:7:" in out


def test_search_code_glob_and_bad_regex(bad_repo):
    tools = RepoTools(bad_repo)
    assert "No matches" in tools.call("search_code", {"pattern": "requests", "path_glob": "*.yml"})
    assert tools.call("search_code", {"pattern": "("}).startswith("ERROR: invalid regular expression")


def test_git_log_lists_commits_and_files(bad_repo):
    out = RepoTools(bad_repo).call("git_log", {"max_count": 5})
    assert "commit 0" in out and "secrets.env" in out


def test_search_git_history_finds_deleted_secret_but_redacts_it(bad_repo):
    out = RepoTools(bad_repo).call("search_git_history", {"pattern": "PASSWORD"})
    assert "secrets.env" in out
    assert "hunter2hunter2" not in out


def test_inspect_workflows_flags_risky_settings(bad_repo):
    out = RepoTools(bad_repo).call("inspect_workflows", {})
    assert "write-all" in out
    assert "continue-on-error=True" in out
    assert '["push"]' in out


def test_inspect_workflows_none(healthy_repo):
    (healthy_repo / ".github/workflows/ci.yml").unlink()
    tools = RepoTools(healthy_repo)
    tools._files = [f for f in tools.tracked_files() if not f.startswith(".github")]
    assert "No GitHub Actions workflows" in tools.call("inspect_workflows", {})


def test_run_pytest_never_runs_on_host_without_sandbox(bad_repo, monkeypatch):
    monkeypatch.setenv("AUDIT_DISABLE_PYTEST", "1")
    (bad_repo / "test_x.py").write_text("def test_x():\n    assert False\n", encoding="utf-8")
    tools = RepoTools(bad_repo)
    tools._files = tools.tracked_files() + ["test_x.py"]
    assert tools.call("run_pytest", {}).startswith("UNAVAILABLE")


def test_tools_do_not_modify_repository(bad_repo):
    import subprocess

    before = subprocess.run(["git", "status", "--porcelain"], cwd=bad_repo, capture_output=True, text=True).stdout
    tools = RepoTools(bad_repo)
    for name, args in [
        ("list_files", {}),
        ("read_file", {"path": "app.py"}),
        ("search_code", {"pattern": "x"}),
        ("git_log", {}),
        ("git_status", {}),
        ("inspect_workflows", {}),
        ("run_ruff", {}),
    ]:
        tools.call(name, args)
    after = subprocess.run(["git", "status", "--porcelain"], cwd=bad_repo, capture_output=True, text=True).stdout
    assert before == after == ""


def test_scan_secrets_finds_current_and_removed_secrets_without_values(bad_repo):
    out = RepoTools(bad_repo).call("scan_secrets", {})
    assert "app.py:3:" in out
    assert "secrets.env" in out and "no longer in current files" in out
    assert FAKE_KEY not in out and "hunter2hunter2" not in out


def test_scan_secrets_flags_committed_env_file_but_not_example(tmp_path):
    from conftest import make_repo

    repo = make_repo(tmp_path / "r", {".env": "DEBUG=1\n", ".env.example": "API_KEY=your-key-here\n"})
    out = RepoTools(repo).call("scan_secrets", {"include_history": False})
    assert ".env: secret-bearing file is committed" in out
    assert ".env.example" not in out
