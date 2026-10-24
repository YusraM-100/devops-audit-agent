"""Collecting, checking and writing violations.

The LLM proposes violations through the ``report_violation`` tool. Before a
finding is accepted, ``Findings.add`` checks it against the real repository:
the file must exist, the line must be inside that file, severity and
category must be valid, and evidence must be given. Rejected findings go back
to the LLM with the reason, so it can investigate again instead of guessing.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from auditor.redact import redact
from auditor.rules import RULES, SEVERITIES, normalize_category

FIELDS = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")
KNOWN_RULES = {r[0]: r for r in RULES}


class Findings:
    def __init__(self, tools):
        self.tools = tools  # RepoTools, used to check file/line evidence
        self.items: list[dict] = []
        self.retracted: list[dict] = []

    def add(self, args: dict) -> str:
        """Validate one proposed violation. Returns a message for the LLM."""
        v = {k: args.get(k) for k in FIELDS}
        problems = []

        rule_id = str(v["rule_id"] or "").strip().upper()
        if not rule_id:
            problems.append("rule_id is required")
        v["rule_id"] = rule_id

        category = normalize_category(v["category"])
        if category is None and rule_id in KNOWN_RULES:
            category = KNOWN_RULES[rule_id][1]
        if category is None:
            problems.append(f"category {v['category']!r} is not one of the allowed categories")
        v["category"] = category

        severity = str(v["severity"] or "").strip().lower()
        if severity not in SEVERITIES:
            problems.append(f"severity must be one of {', '.join(SEVERITIES)}")
        v["severity"] = severity

        for key in ("description", "evidence", "recommendation"):
            v[key] = redact(str(v[key] or "").strip())
            if len(v[key]) < 8:
                problems.append(f"{key} must be a meaningful sentence")

        file = v["file"]
        if file in ("", "null", "None", "N/A"):
            file = None
        if file is not None:
            file = str(file).strip().removeprefix("./").lstrip("/")
            tracked = set(self.tools.tracked_files())
            is_dir = any(f.startswith(file.rstrip("/") + "/") for f in tracked)
            if file not in tracked and not is_dir:
                problems.append(f"file {file!r} is not tracked in the repository; check the exact path with list_files, or use null")
        v["file"] = file

        line = v["line"]
        if line in ("", "null", None, 0):
            line = None
        if line is not None:
            try:
                line = int(line)
            except (TypeError, ValueError):
                problems.append("line must be an integer or null")
                line = None
        if line is not None:
            if file is None:
                problems.append("line given without a file; set line to null")
            else:
                count = self.tools.file_line_count(file)
                if count is None:
                    problems.append(f"{file!r} is not a readable text file; set line to null")
                elif not 1 <= line <= count:
                    problems.append(f"line {line} is outside {file!r} (it has {count} lines); re-check with read_file")
        v["line"] = line

        if problems:
            return (
                "REJECTED: " + "; ".join(problems) + ". Fix and call report_violation again, or drop it if it is not supported by evidence."
            )

        for i, existing in enumerate(self.items, 1):
            if existing is None:
                continue
            if (existing["rule_id"], existing["file"], existing["line"]) == (v["rule_id"], v["file"], v["line"]):
                return f"DUPLICATE of V{i}; not recorded."
            if existing["rule_id"] == v["rule_id"] and existing["file"] == v["file"] and (existing["line"] is None or v["line"] is None):
                return f"DUPLICATE of V{i} (same rule and file); not recorded. Report each distinct occurrence only once."
        self.items.append(v)
        note = "" if rule_id in KNOWN_RULES else " (custom rule_id: make sure no catalogue rule fits better)"
        return f"RECORDED as V{len(self.items)}{note}."

    def retract(self, ref: str, reason: str) -> str:
        ref = str(ref or "").strip().upper().removeprefix("V")
        if not ref.isdigit() or not 1 <= int(ref) <= len(self.items) or self.items[int(ref) - 1] is None:
            return f"ERROR: no active violation V{ref}"
        item = self.items[int(ref) - 1]
        self.items[int(ref) - 1] = None
        self.retracted.append({**item, "retract_reason": redact(str(reason or ""))})
        return f"Retracted V{ref}."

    def active(self) -> list[dict]:
        return [v for v in self.items if v is not None]

    def summary(self) -> str:
        if not self.active():
            return "No violations recorded."
        out = []
        for i, v in enumerate(self.items, 1):
            if v is not None:
                where = f"{v['file']}:{v['line']}" if v["line"] else (v["file"] or "repository")
                out.append(f"V{i} {v['rule_id']} [{v['severity']}] {where} - {v['description']} | evidence: {v['evidence']}")
        return "\n".join(out)


_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def build_report(repository: str, violations: list[dict]) -> dict:
    ordered = sorted(violations, key=lambda v: (_ORDER[v["severity"]], v["category"], v["rule_id"], v["file"] or "", v["line"] or 0))
    return {"repository": repository, "violations": [{k: v[k] for k in FIELDS} for v in ordered]}


def validate_report(report: dict) -> list[str]:
    """Check a report against the output contract. Returns a list of problems (empty = valid)."""
    errors = []
    if not isinstance(report, dict):
        return ["report must be a JSON object"]
    if not isinstance(report.get("repository"), str):
        errors.append("repository must be a string")
    violations = report.get("violations")
    if not isinstance(violations, list):
        return errors + ["violations must be a list"]
    for i, v in enumerate(violations):
        missing = [f for f in FIELDS if f not in v]
        if missing:
            errors.append(f"violation {i}: missing {missing}")
            continue
        if v["severity"] not in SEVERITIES:
            errors.append(f"violation {i}: bad severity {v['severity']!r}")
        if v["file"] is not None and not isinstance(v["file"], str):
            errors.append(f"violation {i}: file must be string or null")
        if v["line"] is not None and (not isinstance(v["line"], int) or isinstance(v["line"], bool)):
            errors.append(f"violation {i}: line must be integer or null")
        for key in ("rule_id", "category", "description", "evidence", "recommendation"):
            if not isinstance(v[key], str) or not v[key]:
                errors.append(f"violation {i}: {key} must be a non-empty string")
    return errors


def write_json(path: str | Path, data) -> None:
    """Write JSON atomically so a crash never leaves a half-written report."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
