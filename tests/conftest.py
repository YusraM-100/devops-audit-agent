"""Shared test fixtures: small throw-away git repositories with known defects."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor.llm import LLMResponse, ToolCall  # noqa: E402


def make_repo(root: Path, files: dict[str, str], commits: list[dict[str, str | None]] | None = None) -> Path:
    """Create a git repo. ``files`` is the final state; ``commits`` are earlier states (None deletes a file)."""
    root.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,  # ignore the developer's own git settings (signing, autocrlf, ...)
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def run(*args):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, env=env)

    run("init", "-q", "-b", "main")
    for i, state in enumerate((commits or []) + [files]):
        for name, content in state.items():
            path = root / name
            if content is None:
                path.unlink(missing_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        run("add", "-A")
        run("commit", "-q", "-m", f"commit {i}", "--allow-empty")
    return root


FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # split so this file itself does not look like a leak

BAD_FILES = {
    "app.py": "import requests\n\nAWS_KEY = '"
    + FAKE_KEY
    + "'\nDATA = 'C:\\\\Users\\\\bob\\\\data.csv'\n\ndef main():\n    return requests.get('https://x', verify=False)\n",
    "requirements.txt": "requests\nflask\n",
    "__pycache__/app.cpython-312.pyc": "junk",
    ".github/workflows/ci.yml": (
        "name: CI\non: [push]\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - run: pytest\n        continue-on-error: true\n"
    ),
}

HEALTHY_FILES = {
    "README.md": "# Demo\n\nInstall with `pip install -r requirements.txt` and run `pytest`.\n",
    ".gitignore": "__pycache__/\n*.pyc\n.env\n",
    "requirements.txt": "requests==2.32.3\n",
    "app.py": "import os\n\nimport requests\n\nAPI_KEY = os.environ['API_KEY']\n\n\ndef ping():\n    return requests.get('https://example.com', timeout=5)\n",
    "tests/test_app.py": "def test_ok():\n    assert True\n",
    "pyproject.toml": "[tool.ruff]\nline-length = 100\n",
    ".github/workflows/ci.yml": (
        "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pip install -r requirements.txt\n"
        "      - run: ruff check .\n      - run: pytest\n"
    ),
}


@pytest.fixture
def bad_repo(tmp_path):
    return make_repo(tmp_path / "bad", BAD_FILES, commits=[{"secrets.env": "DB_PASSWORD=hunter2hunter2\n"}, {"secrets.env": None}])


@pytest.fixture
def healthy_repo(tmp_path):
    return make_repo(tmp_path / "healthy", HEALTHY_FILES)


class ScriptedLLM:
    """A fake LLM. Each entry is a list of (tool_name, args) to request, or a callable(messages) -> LLMResponse."""

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[list[dict]] = []

    def chat(self, system, messages, tools):
        self.calls.append([dict(m) for m in messages])
        if not self.script:
            return LLMResponse(text="done", tool_calls=[])
        step = self.script.pop(0)
        if callable(step):
            return step(messages)
        return LLMResponse(
            text="reasoning",
            tool_calls=[ToolCall(id=f"c{len(self.calls)}_{i}", name=n, arguments=a) for i, (n, a) in enumerate(step)],
        )


ALL_CATEGORIES_NOTE = {
    c: "checked"
    for c in [
        "repository_hygiene",
        "dependency_management",
        "code_quality",
        "testing",
        "ci",
        "security",
        "configuration",
        "collaboration",
        "build_release",
    ]
}
