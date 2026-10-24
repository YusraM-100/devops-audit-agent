"""Build three local practice repositories with known (injected) defects.

    python benchmarks/make_repos.py /tmp/bench

creates /tmp/bench/{obvious,subtle,healthy}, each a git repository plus an
expected.json answer key next to it. They mirror the three kinds of hidden
repositories used for grading. Run the agent on each and score it:

    python agent.py --repo /tmp/bench/obvious --output /tmp/bench/obvious.report.json
    python evaluate.py --report /tmp/bench/obvious.report.json --expected /tmp/bench/obvious.expected.json
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

FAKE_AWS = "AKIA" + "Z7QW3ERTY5UIOP2A"
FAKE_STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"

REPOS = {
    "obvious": {
        "history": [{"config.py": f"STRIPE_KEY = '{FAKE_STRIPE}'\n"}, {"config.py": "import os\nSTRIPE_KEY = os.environ['STRIPE_KEY']\n"}],
        "files": {
            "app.py": (
                "import requests\nfrom flask import Flask\n\n"
                f"AWS_ACCESS_KEY_ID = '{FAKE_AWS}'\n"
                "DATA_DIR = 'C:\\\\Users\\\\ahmed\\\\Desktop\\\\data'\n\n"
                "app = Flask(__name__)\n\n\n@app.route('/')\ndef index():\n    return requests.get('https://api.example.com').text\n"
            ),
            "config.py": "import os\nSTRIPE_KEY = os.environ['STRIPE_KEY']\n",
            "requirements.txt": "flask\nrequests\n",
            "__pycache__/app.cpython-312.pyc": "\x00compiled",
            ".DS_Store": "\x00\x01",
        },
        "expected": [
            {"rule_id": "HYG-001", "category": "repository_hygiene", "file": None},
            {"rule_id": "HYG-002", "category": "repository_hygiene", "file": None},
            {"rule_id": "HYG-003", "category": "repository_hygiene", "file": "__pycache__/app.cpython-312.pyc"},
            {"rule_id": "DEP-002", "category": "dependency_management", "file": "requirements.txt"},
            {"rule_id": "TST-001", "category": "testing", "file": None},
            {"rule_id": "SEC-001", "category": "security", "file": "app.py"},
            {"rule_id": "SEC-003", "category": "security", "file": "config.py"},
            {"rule_id": "CFG-001", "category": "configuration", "file": "app.py"},
        ],
    },
    "subtle": {
        "files": {
            "README.md": "# Billing service\n\nRun `pip install -r requirements.txt` then `pytest`.\n",
            ".gitignore": "__pycache__/\n*.pyc\n.env\n",
            "requirements.txt": "requests==2.32.3\npyyaml==6.0.2\n",
            "billing.py": (
                "import requests\nimport yaml\n\n\ndef load(path):\n    with open(path) as fh:\n        return yaml.load(fh, Loader=yaml.Loader)\n\n\n"
                "def charge(amount):\n    return requests.post('https://pay.internal/charge', json={'a': amount}, verify=False, timeout=5)\n"
            ),
            "tests/test_billing.py": "from billing import load\n\n\ndef test_load(tmp_path):\n    p = tmp_path / 'x.yml'\n    p.write_text('a: 1')\n    assert load(p) == {'a': 1}\n",
            "pyproject.toml": "[tool.ruff]\nline-length = 100\n",
            ".github/workflows/ci.yml": (
                "name: CI\non:\n  push:\n    branches: [master]\n  pull_request_target:\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                '      - run: echo "Testing ${{ github.event.pull_request.title }}"\n'
                "      - run: pip install -r requirements.txt pytest ruff\n      - run: ruff check . || true\n"
                "      - run: pytest\n        continue-on-error: true\n"
            ),
            ".github/workflows/deploy.yml": (
                "name: Deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
                "      - uses: someone/deploy-action@main\n        with:\n          token: ${{ secrets.DEPLOY_TOKEN }}\n"
                "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n"
            ),
            ".vscode/settings.json": '{"python.defaultInterpreterPath": "/Users/sara/venvs/billing/bin/python"}\n',
        },
        "expected": [
            {"rule_id": "CI-002", "category": "ci", "file": ".github/workflows/ci.yml"},
            {"rule_id": "CI-003", "category": "ci", "file": ".github/workflows/ci.yml"},
            {"rule_id": "CI-005", "category": "ci", "file": ".github/workflows/deploy.yml"},
            {"rule_id": "SEC-004", "category": "security", "file": ".github/workflows/ci.yml"},
            {"rule_id": "SEC-005", "category": "security", "file": ".github/workflows/ci.yml"},
            {"rule_id": "SEC-006", "category": "security", "file": ".github/workflows/deploy.yml"},
            {"rule_id": "SEC-007", "category": "security", "file": "billing.py"},
            {"rule_id": "BLD-002", "category": "build_release", "file": ".github/workflows/deploy.yml"},
            {"rule_id": "CFG-002", "category": "configuration", "file": ".vscode/settings.json"},
        ],
    },
    "healthy": {
        "files": {
            "README.md": "# Weather CLI\n\n## Install\n\n```\npip install -e .[dev]\n```\n\n## Test\n\n```\npytest\n```\n",
            ".gitignore": "__pycache__/\n*.pyc\n.venv/\n.env\ndist/\n",
            "pyproject.toml": (
                '[project]\nname = "weather"\nversion = "0.1.0"\ndependencies = ["httpx>=0.27,<1"]\n\n'
                '[project.optional-dependencies]\ndev = ["pytest>=8", "ruff>=0.6"]\n\n[tool.ruff]\nline-length = 100\n'
            ),
            "src/weather/__init__.py": "",
            "src/weather/cli.py": (
                "import os\n\nimport httpx\n\nAPI_URL = os.environ.get('WEATHER_API_URL', 'https://api.example.com')\n\n\n"
                "def get(city: str) -> dict:\n    resp = httpx.get(f'{API_URL}/{city}', headers={'key': os.environ['WEATHER_KEY']}, timeout=10)\n"
                "    resp.raise_for_status()\n    return resp.json()\n"
            ),
            "tests/test_cli.py": "def test_import():\n    import weather.cli  # noqa: F401\n",
            ".env.example": "WEATHER_KEY=your-key-here\nWEATHER_API_URL=https://api.example.com\n",
            ".github/workflows/ci.yml": (
                "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n"
                "      - run: pip install -e .[dev]\n      - run: ruff check .\n      - run: pytest\n"
            ),
        },
        "expected": [],
    },
}


def build(root: Path) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Bench",
        "GIT_AUTHOR_EMAIL": "bench@example.com",
        "GIT_COMMITTER_NAME": "Bench",
        "GIT_COMMITTER_EMAIL": "bench@example.com",
    }
    for name, spec in REPOS.items():
        repo = root / name
        if repo.exists():
            sys.exit(f"{repo} already exists; choose an empty directory")
        repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        for i, state in enumerate(spec.get("history", []) + [spec["files"]]):
            for rel, content in state.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
            subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", f"change {i + 1}"], cwd=repo, check=True, env=env)
        (root / f"{name}.expected.json").write_text(
            json.dumps({"repository": str(repo), "violations": spec["expected"]}, indent=2), encoding="utf-8"
        )
        print(f"created {repo} ({len(spec['expected'])} known violations)")


if __name__ == "__main__":
    build(Path(sys.argv[1] if len(sys.argv) > 1 else "bench").resolve())
