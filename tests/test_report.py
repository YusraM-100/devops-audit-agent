"""Findings are validated against the real repository before they are accepted."""

from auditor.report import Findings, build_report, validate_report
from tools import RepoTools

GOOD = {
    "rule_id": "SEC-001",
    "category": "security",
    "severity": "critical",
    "file": "app.py",
    "line": 3,
    "description": "Hardcoded AWS access key",
    "evidence": "app.py line 3 assigns a literal key",
    "recommendation": "Load the key from an environment variable",
}


def test_valid_finding_recorded(bad_repo):
    f = Findings(RepoTools(bad_repo))
    assert f.add(GOOD).startswith("RECORDED as V1")


def test_rejects_missing_file_bad_line_and_bad_severity(bad_repo):
    f = Findings(RepoTools(bad_repo))
    assert "not tracked" in f.add({**GOOD, "file": "nope.py"})
    assert "outside" in f.add({**GOOD, "line": 999})
    assert "severity" in f.add({**GOOD, "severity": "urgent"})
    assert f.active() == []


def test_duplicates_and_retraction(bad_repo):
    f = Findings(RepoTools(bad_repo))
    f.add(GOOD)
    assert f.add(GOOD).startswith("DUPLICATE")
    assert f.retract("V1", "wrong") == "Retracted V1."
    assert f.active() == []
    assert f.add(GOOD).startswith("RECORDED")


def test_null_file_line_and_category_alias(bad_repo):
    f = Findings(RepoTools(bad_repo))
    msg = f.add({**GOOD, "rule_id": "TST-001", "category": "tests", "file": None, "line": None})
    assert msg.startswith("RECORDED")
    assert f.active()[0]["category"] == "testing"


def test_report_shape_is_valid_and_sorted(bad_repo):
    f = Findings(RepoTools(bad_repo))
    f.add({**GOOD, "rule_id": "QUA-002", "category": "code_quality", "severity": "low", "line": 1})
    f.add(GOOD)
    report = build_report("https://github.com/a/b", f.active())
    assert validate_report(report) == []
    assert [v["severity"] for v in report["violations"]] == ["critical", "low"]
    assert list(report["violations"][0]) == ["rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"]


def test_validate_report_catches_problems():
    assert validate_report({"repository": "x", "violations": [{"rule_id": "A"}]})
    assert validate_report({"repository": "x", "violations": []}) == []
