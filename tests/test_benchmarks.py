"""The practice repositories build correctly and their answer keys use real rule ids."""

import json
import subprocess
import sys
from pathlib import Path

from auditor.rules import CATEGORIES, RULES

ROOT = Path(__file__).resolve().parents[1]


def test_benchmark_repos_build(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "benchmarks/make_repos.py"), str(tmp_path)], check=True, capture_output=True)
    rule_ids = {r[0] for r in RULES}
    for name in ("obvious", "subtle", "healthy"):
        assert (tmp_path / name / ".git").is_dir()
        for v in json.loads((tmp_path / f"{name}.expected.json").read_text(encoding="utf-8"))["violations"]:
            assert v["rule_id"] in rule_ids and v["category"] in CATEGORIES
