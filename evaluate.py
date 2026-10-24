"""Score a report against an answer key (precision and recall).

    python evaluate.py --report report.json --expected expected.json

expected.json uses the same format as the report, but only needs
"category" and "file" (and optionally "rule_id") for each known violation.
A reported violation matches a known one when the category and file agree
(and the rule_id too, if the answer key gives one). Each known violation can
be matched only once, so duplicates do not count twice.
"""

from __future__ import annotations

import argparse
import json
import sys


def score(reported: list[dict], expected: list[dict]) -> dict:
    unmatched = list(expected)
    true_positives = 0
    for v in reported:
        for known in unmatched:
            same_rule = "rule_id" not in known or known["rule_id"] == v.get("rule_id")
            if same_rule and known.get("category") == v.get("category") and known.get("file") == v.get("file"):
                unmatched.remove(known)
                true_positives += 1
                break
    precision = true_positives / len(reported) if reported else (1.0 if not expected else 0.0)
    recall = true_positives / len(expected) if expected else 1.0
    return {
        "true_positives": true_positives,
        "reported": len(reported),
        "expected": len(expected),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "missed": unmatched,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--report", required=True)
    p.add_argument("--expected", required=True)
    args = p.parse_args(argv)
    with open(args.report) as fh:
        reported = json.load(fh)["violations"]
    with open(args.expected) as fh:
        expected = json.load(fh)["violations"]
    print(json.dumps(score(reported, expected), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
