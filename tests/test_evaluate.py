from evaluate import score


def test_precision_and_recall():
    expected = [{"category": "security", "file": "a.py"}, {"category": "testing", "file": None}]
    reported = [{"category": "security", "file": "a.py"}, {"category": "security", "file": "a.py"}, {"category": "ci", "file": "x.yml"}]
    s = score(reported, expected)
    assert s["true_positives"] == 1  # the duplicate earns nothing
    assert s["precision"] == round(1 / 3, 3) and s["recall"] == 0.5


def test_healthy_repo_with_no_findings_is_perfect():
    assert score([], [])["precision"] == 1.0
