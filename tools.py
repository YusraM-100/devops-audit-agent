"""Inspection tools the agent can call.

Every tool:
  * is read-only (the inspected repository is never changed),
  * never executes code from the inspected repository on the host,
  * returns plain text (what the LLM reads), already passed through the
    secret redactor and capped in size,
  * reports problems as text (``ERROR: ...``) instead of raising, so one bad
    call never crashes the whole audit.

``RepoTools.SCHEMAS`` describes the tools to the LLM (JSON Schema), and
``RepoTools.call(name, args)`` is the single dispatch point the agent loop
uses.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

from auditor.redact import redact
from auditor.repo import git

MAX_OUTPUT_CHARS = 12_000
MAX_FILE_BYTES = 1_000_000
MAX_READ_LINES = 400


SENSITIVE_FILE = re.compile(
    r"^(\.env(\..+)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx|credentials\.json|"
    r"service[-_]account.*\.json|\.npmrc|\.pypirc|\.netrc|\.htpasswd|secrets?\.(ya?ml|json|env))$",
    re.IGNORECASE,
)


class ToolError(Exception):
    """A tool was called with bad arguments or could not complete."""


def _cap(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [output truncated: {len(text) - limit} more characters. Narrow the request.]"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


class RepoTools:
    """All inspection tools, bound to one cloned repository."""

    SCHEMAS = [
        {
            "name": "list_files",
            "description": (
                "List files tracked in the repository (what is committed), with sizes. "
                "Use path to look inside one directory. Start here to discover structure."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory relative to repo root. Default: root."},
                    "max_depth": {"type": "integer", "description": "How many directory levels to show (default 6)."},
                },
            },
        },
        {
            "name": "read_file",
            "description": "Read a text file with line numbers. Use start_line/end_line for long files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to repo root."},
                    "start_line": {"type": "integer", "description": "First line to show (1-based)."},
                    "end_line": {"type": "integer", "description": "Last line to show (inclusive)."},
                },
                "required": ["path"],
            },
        },
        {
            "name": "search_code",
            "description": (
                "Search all tracked text files for a regular expression (Python syntax). "
                "Returns file:line: text matches. Use to find suspicious patterns such as credentials, "
                "absolute paths, 'continue-on-error', 'verify=False'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression to search for."},
                    "path_glob": {"type": "string", "description": "Only search files matching this glob, e.g. '*.py' or '.github/*'."},
                    "case_insensitive": {"type": "boolean", "description": "Ignore case (default true)."},
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "git_log",
            "description": "Show recent commit history: hash, date, author, message and the files each commit changed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_count": {"type": "integer", "description": "Number of commits (default 30, max 200)."},
                    "path": {"type": "string", "description": "Only commits touching this path."},
                },
            },
        },
        {
            "name": "search_git_history",
            "description": (
                "Search every commit's added/removed lines for a regex (git log -G). Finds things that were "
                "committed and later deleted, e.g. secrets that still live in history."
            ),
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string", "description": "Regular expression (POSIX extended)."}},
                "required": ["pattern"],
            },
        },
        {
            "name": "scan_secrets",
            "description": (
                "Secret scanner: finds lines that look like hardcoded credentials (API keys, tokens, passwords, private keys, "
                "credentials in URLs) in current files AND in git history, plus secret-bearing files such as .env or id_rsa. "
                "Values are always shown as [REDACTED]. Verify each hit (placeholder? test fixture?) before reporting."
            ),
            "parameters": {
                "type": "object",
                "properties": {"include_history": {"type": "boolean", "description": "Also scan all commits (default true)."}},
            },
        },
        {
            "name": "git_status",
            "description": "Show working-tree status, branches and tags of the clone.",
            "parameters": {
                "type": "object",
                "properties": {"include_tags": {"type": "boolean", "description": "Also list tags (default true)."}},
            },
        },
        {
            "name": "inspect_workflows",
            "description": (
                "Parse every GitHub Actions workflow (.github/workflows/*.yml) and summarise triggers, "
                "permissions, jobs, steps, continue-on-error, conditions, actions used and secret usage."
            ),
            "parameters": {
                "type": "object",
                "properties": {"file": {"type": "string", "description": "Only this workflow file. Default: all workflows."}},
            },
        },
        {
            "name": "run_ruff",
            "description": (
                "Run the Ruff linter (static analysis only, does not execute repository code) and summarise "
                "findings by rule. Uses the repository's own Ruff configuration if present."
            ),
            "parameters": {
                "type": "object",
                "properties": {"select": {"type": "string", "description": "Optional rule selection, e.g. 'E,F,B'."}},
            },
        },
        {
            "name": "run_pytest",
            "description": (
                "Run the repository's tests inside an isolated Docker container (no access to the host). "
                "Only available when Docker is installed; otherwise reports that it could not run."
            ),
            "parameters": {
                "type": "object",
                "properties": {"test_path": {"type": "string", "description": "Only run tests under this path. Default: all tests."}},
            },
        },
    ]

    def __init__(self, root: Path, *, command_timeout: int = 60, pytest_timeout: int = 600):
        self.root = Path(root).resolve()
        self.command_timeout = command_timeout
        self.pytest_timeout = pytest_timeout
        self._files: list[str] | None = None

    # ------------------------------------------------------------------ helpers
    def tracked_files(self) -> list[str]:
        """Files committed to the repository (falls back to a walk if not a git repo)."""
        if self._files is None:
            result = git(["ls-files", "-z"], cwd=self.root, timeout=self.command_timeout)
            if result.returncode == 0 and (self.root / ".git").exists():
                self._files = sorted(f for f in result.stdout.split("\0") if f)
            else:
                files = []
                for dirpath, dirnames, filenames in os.walk(self.root):
                    dirnames[:] = [d for d in dirnames if d != ".git"]
                    for name in filenames:
                        files.append(str(Path(dirpath, name).relative_to(self.root)).replace(os.sep, "/"))
                self._files = sorted(files)
        return self._files

    def resolve(self, rel: str) -> Path:
        """Turn a repo-relative path into an absolute one, refusing to escape the repo."""
        rel = (rel or ".").strip().lstrip("/") or "."
        path = (self.root / rel).resolve()
        if path != self.root and self.root not in path.parents:
            raise ToolError(f"path {rel!r} is outside the repository")
        return path

    def file_line_count(self, rel: str) -> int | None:
        """Number of lines in a tracked text file, or None if unreadable."""
        try:
            data = self.resolve(rel).read_bytes()
        except (OSError, ToolError):
            return None
        if _is_binary(data):
            return None
        return data.decode("utf-8", errors="replace").count("\n") + 1

    def call(self, name: str, args: dict | None) -> str:
        """Dispatch a tool call by name. Always returns text, never raises."""
        args = args or {}
        method = getattr(self, name, None)
        if name not in {s["name"] for s in self.SCHEMAS} or method is None:
            return f"ERROR: unknown tool {name!r}"
        try:
            output = method(**args)
        except TypeError as exc:
            return f"ERROR: bad arguments for {name}: {exc}"
        except ToolError as exc:
            return f"ERROR: {exc}"
        except subprocess.TimeoutExpired:
            return f"ERROR: {name} timed out"
        except Exception as exc:  # noqa: BLE001 - a tool must never crash the agent
            return f"ERROR: {name} failed: {type(exc).__name__}: {exc}"
        return _cap(redact(output))

    # -------------------------------------------------------------------- tools
    def list_files(self, path: str = ".", max_depth: int = 6) -> str:
        base = self.resolve(path)
        prefix = "" if base == self.root else str(base.relative_to(self.root)).replace(os.sep, "/") + "/"
        files = [f for f in self.tracked_files() if f.startswith(prefix)]
        if not files:
            return f"No tracked files under {path!r}."
        lines, hidden = [], 0
        max_depth = max(1, int(max_depth or 6))
        for f in files:
            if f[len(prefix) :].count("/") >= max_depth:
                hidden += 1
                continue
            try:
                size = (self.root / f).lstat().st_size
            except OSError:
                size = 0
            lines.append(f"{f}  ({size} bytes)")
        header = f"{len(files)} tracked file(s) under {path!r}"
        if hidden:
            header += f" ({hidden} deeper than depth {max_depth} not shown)"
        if len(lines) > 600:
            lines = lines[:600] + [f"... {len(lines) - 600} more; use path= to look inside a directory"]
        return header + "\n" + "\n".join(lines)

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        target = self.resolve(path)
        if not target.exists():
            raise ToolError(f"file {path!r} does not exist")
        if target.is_dir():
            raise ToolError(f"{path!r} is a directory; use list_files")
        size = target.stat().st_size
        with open(target, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES)
        if _is_binary(data):
            return f"{path} is a binary file ({size} bytes); contents not shown."
        lines = data.decode("utf-8", errors="replace").splitlines()
        total = len(lines)
        start = max(1, int(start_line or 1))
        end = min(total, int(end_line) if end_line else start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1)
        if total == 0:
            return f"{path} is empty (0 lines)."
        if start > total:
            raise ToolError(f"{path} has only {total} lines")
        body = "\n".join(f"{n:>5}| {lines[n - 1][:500]}" for n in range(start, end + 1))
        note = f"{path} (lines {start}-{end} of {total}"
        note += ", file truncated at 1 MB)" if size > MAX_FILE_BYTES else ")"
        if end < total:
            note += f" - call again with start_line={end + 1} to continue"
        return note + "\n" + body

    def search_code(self, pattern: str, path_glob: str | None = None, case_insensitive: bool = True) -> str:
        if not pattern or len(pattern) > 300:
            raise ToolError("pattern must be 1-300 characters")
        try:
            regex = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc
        matches, files_hit, limit, total = [], set(), 150, 0
        for rel in self.tracked_files():
            if path_glob and not (fnmatch.fnmatch(rel, path_glob) or fnmatch.fnmatch(Path(rel).name, path_glob)):
                continue
            try:
                data = (self.root / rel).read_bytes()[:MAX_FILE_BYTES]
            except OSError:
                continue
            if _is_binary(data):
                continue
            for n, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    total += 1
                    files_hit.add(rel)
                    if len(matches) < limit:
                        matches.append(f"{rel}:{n}: {line.strip()[:300]}")
        if not matches:
            return f"No matches for /{pattern}/" + (f" in files matching {path_glob!r}" if path_glob else "")
        header = f"{total} match(es) in {len(files_hit)} file(s)"
        if total > limit:
            header += f" (showing first {limit}; refine the pattern)"
        return header + "\n" + "\n".join(matches)

    def git_log(self, max_count: int = 30, path: str | None = None) -> str:
        if not (self.root / ".git").exists():
            return "Not a git repository: no commit history available."
        count = min(max(1, int(max_count or 30)), 200)
        args = ["log", f"--max-count={count}", "--date=short", "--name-status", "--format=--- %h %ad %an%n    %s"]
        if path:
            args += ["--", path]
        result = git(args, cwd=self.root, timeout=self.command_timeout)
        if result.returncode != 0:
            raise ToolError(result.stderr.strip() or "git log failed")
        authors = git(["shortlog", "-sn", "HEAD"], cwd=self.root, timeout=self.command_timeout)
        return f"Authors (commits per author):\n{authors.stdout.rstrip()}\n\nLast {count} commits:\n{result.stdout.rstrip()}"

    def search_git_history(self, pattern: str) -> str:
        if not (self.root / ".git").exists():
            return "Not a git repository: no history to search."
        if not pattern or len(pattern) > 200:
            raise ToolError("pattern must be 1-200 characters")
        result = git(
            ["log", "--all", "-G", pattern, "--extended-regexp", "-i", "-p", "--unified=0", "--format=@@commit %h %ad %s", "--date=short"],
            cwd=self.root,
            timeout=self.command_timeout * 2,
        )
        if result.returncode != 0:
            raise ToolError(result.stderr.strip() or "git log failed")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = None
        out, current_file = [], None
        for line in result.stdout.splitlines():
            if line.startswith("@@commit"):
                out.append(line[2:])
            elif line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                if regex is None or regex.search(line):
                    out.append(f"   {current_file}: {line[:250]}")
        if not out:
            return f"Pattern /{pattern}/ never appears in any commit."
        return "Matches in history (+ added, - removed):\n" + "\n".join(out[:300])

    def scan_secrets(self, include_history: bool = True) -> str:
        hits, current = [], set()
        for rel in self.tracked_files():
            name = Path(rel).name
            if SENSITIVE_FILE.search(name) and not re.search(r"example|sample|template|dist$", name, re.IGNORECASE):
                hits.append(f"{rel}: secret-bearing file is committed")
            try:
                data = (self.root / rel).read_bytes()[:MAX_FILE_BYTES]
            except OSError:
                continue
            if _is_binary(data):
                continue
            for n, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if len(line) > 1000:  # minified files: skip
                    continue
                masked = redact(line)
                if masked != line:
                    current.add(masked.strip())
                    hits.append(f"{rel}:{n}: {masked.strip()[:200]}")
        out = [
            "Each hit is a real-looking literal (placeholders, env lookups and variable references are never redacted).",
            f"Current files: {len(hits)} likely hardcoded secret(s)",
        ] + hits[:100]
        if include_history and (self.root / ".git").exists():
            result = git(
                ["log", "--all", "-p", "--unified=0", "--no-color", "--format=@@commit %h %ad", "--date=short"],
                cwd=self.root,
                timeout=self.command_timeout * 2,
            )
            commit, file, history = "", "", []
            for line in result.stdout.splitlines()[:300_000]:
                if line.startswith("@@commit "):
                    commit = line[9:]
                elif line.startswith("+++ b/"):
                    file = line[6:]
                elif line.startswith("+") and not line.startswith("+++") and len(line) < 1000:
                    masked = redact(line[1:])
                    if masked != line[1:] and masked.strip() not in current:
                        history.append(f"commit {commit} {file}: {masked.strip()[:160]} (no longer in current files)")
            out.append(f"\nGit history: {len(history)} secret-like line(s) that were committed and later removed")
            out += history[:100]
        return "\n".join(out)

    def git_status(self, include_tags: bool = True) -> str:
        if not (self.root / ".git").exists():
            return "Not a git repository."
        parts = []
        for title, args in [
            ("Status", ["status", "--short", "--branch"]),
            ("Branches", ["branch", "-a"]),
            ("Tags", ["tag", "--list"]),
        ]:
            if title == "Tags" and not include_tags:
                continue
            result = git(args, cwd=self.root, timeout=self.command_timeout)
            parts.append(f"{title}:\n{result.stdout.rstrip() or '(none)'}")
        return "\n\n".join(parts)

    def inspect_workflows(self, file: str | None = None) -> str:
        workflows = [f for f in self.tracked_files() if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f)]
        if file:
            workflows = [f for f in workflows if f == file.strip().removeprefix("./")]
            if not workflows:
                raise ToolError(f"{file!r} is not a tracked workflow file")
        other_ci = [
            f
            for f in self.tracked_files()
            if f
            in (
                ".gitlab-ci.yml",
                "Jenkinsfile",
                ".travis.yml",
                "azure-pipelines.yml",
                "bitbucket-pipelines.yml",
                "tox.ini",
                "noxfile.py",
                ".pre-commit-config.yaml",
            )
            or f.startswith(".circleci/")
        ]
        if not workflows:
            msg = "No GitHub Actions workflows found in .github/workflows/."
            if other_ci:
                msg += f" Other CI/automation config present: {', '.join(other_ci)}"
            return msg
        report = []
        for wf in workflows:
            report.append(_summarise_workflow(wf, (self.root / wf).read_text(encoding="utf-8", errors="replace")))
        if other_ci:
            report.append(f"Other CI/automation config present: {', '.join(other_ci)}")
        return "\n\n".join(report)

    def run_ruff(self, select: str | None = None) -> str:
        ruff = shutil.which("ruff")
        if not ruff:
            return "UNAVAILABLE: ruff is not installed, so linting could not be checked. Do not report lint results."
        if not any(f.endswith(".py") for f in self.tracked_files()):
            return "No Python files to lint."
        args = [ruff, "check", ".", "--no-cache", "--output-format=concise", "--exit-zero", "--no-fix"]
        has_config = any(f in ("ruff.toml", ".ruff.toml") for f in self.tracked_files()) or (
            "[tool.ruff" in (self.root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
            if (self.root / "pyproject.toml").is_file()
            else False
        )
        if not has_config:
            args.append("--isolated")  # ruff defaults only; ignore any config outside the repository
        if select:
            if not re.fullmatch(r"[A-Z0-9,]+", select):
                raise ToolError("select must look like 'E,F,B'")
            args += ["--select", select]
        result = subprocess.run(args, cwd=self.root, capture_output=True, text=True, timeout=self.command_timeout, errors="replace")
        lines = [ln for ln in result.stdout.splitlines() if re.match(r".+:\d+:\d+: ", ln)]
        if not lines:
            return "Ruff found no issues." + (f"\n{result.stderr.strip()}" if result.stderr.strip() else "")
        counts: dict[str, int] = {}
        for ln in lines:
            code = ln.split(": ", 1)[1].split(" ", 1)[0]
            counts[code] = counts.get(code, 0) + 1
        summary = ", ".join(f"{c}x{n}" for c, n in sorted(counts.items(), key=lambda kv: -kv[1]))
        source = "repository's ruff config" if has_config else "ruff default rules (no ruff config in repo)"
        return f"Ruff ({source}): {len(lines)} issue(s). By rule: {summary}\n" + "\n".join(lines[:80])

    def run_pytest(self, test_path: str | None = None) -> str:
        target = ""
        if test_path:
            if not re.fullmatch(r"[\w./-]+", test_path) or ".." in test_path:
                raise ToolError("test_path must be a plain relative path")
            target = " " + test_path
        if not any(re.search(r"(^|/)(test_[^/]*|[^/]*_test)\.py$", f) for f in self.tracked_files()):
            return "No pytest-style test files (test_*.py / *_test.py) found; nothing to run."
        docker = shutil.which("docker")
        if not docker or os.environ.get("AUDIT_DISABLE_PYTEST") == "1":
            return (
                "UNAVAILABLE: tests were NOT run because no isolated sandbox (Docker) is available. "
                "Untrusted repository code is never executed on the host. Do not report test pass/fail results."
            )
        try:
            alive = subprocess.run([docker, "info"], capture_output=True, timeout=20).returncode == 0
        except subprocess.TimeoutExpired:
            alive = False
        if not alive:
            return (
                "UNAVAILABLE: Docker is installed but its daemon is not reachable, so tests were NOT run. "
                "Untrusted repository code is never executed on the host. Do not report test pass/fail results."
            )
        script = (
            "cp -r /repo /work && cd /work && "
            "(pip install -q -r requirements.txt >/dev/null 2>&1 || pip install -q . >/dev/null 2>&1 || true) && "
            f"pip install -q pytest >/dev/null 2>&1; python -m pytest -q --no-header -rfE{target} 2>&1 | tail -n 60"
        )
        cmd = [
            docker,
            "run",
            "--rm",
            "--memory=1g",
            "--cpus=1",
            "--pids-limit=256",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "-v",
            f"{self.root}:/repo:ro",
            os.environ.get("AUDIT_PYTEST_IMAGE", "python:3.12-slim"),
            "sh",
            "-c",
            script,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.pytest_timeout, errors="replace")
        except subprocess.TimeoutExpired:
            return f"UNAVAILABLE: test run exceeded {self.pytest_timeout}s and was stopped; result unknown."
        if result.returncode == 125 or (result.returncode != 0 and not result.stdout.strip()):
            return f"UNAVAILABLE: could not start the sandbox: {result.stderr.strip()[-300:]}"
        return "Pytest output (inside isolated container):\n" + (result.stdout or result.stderr).strip()[-6000:]


# ---------------------------------------------------------------- workflows
_EXPR_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|commits|discussion|pages)[^}]*|head_ref)\s*\}\}"
)


def _summarise_workflow(name: str, text: str) -> str:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return f"## {name}\nINVALID YAML: {str(exc).splitlines()[0]}"
    if not isinstance(data, dict):
        return f"## {name}\nNot a mapping; workflow is invalid."
    # PyYAML (YAML 1.1) turns the key `on` into True.
    triggers = data.get("on", data.get(True))
    lines = [f"## {name}", f"name: {data.get('name', '(none)')}", f"triggers: {json.dumps(triggers, default=str)}"]
    lines.append(f"top-level permissions: {json.dumps(data.get('permissions', 'NOT SET (repository default applies)'), default=str)}")
    if data.get("env"):
        lines.append(f"workflow env keys: {list(data['env'])}")
    jobs = data.get("jobs") or {}
    if not isinstance(jobs, dict):
        lines.append("jobs: invalid")
        return "\n".join(lines)
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        lines.append(
            f"- job {job_id}: runs-on={job.get('runs-on')} needs={job.get('needs')} if={job.get('if')}"
            f" continue-on-error={job.get('continue-on-error')} permissions={json.dumps(job.get('permissions'), default=str)}"
            f" environment={job.get('environment')}"
        )
        if job.get("uses"):
            lines.append(f"    reusable workflow: {job['uses']}")
        for i, step in enumerate(job.get("steps") or [], 1):
            if not isinstance(step, dict):
                continue
            desc = step.get("name") or ""
            if step.get("uses"):
                desc += f" uses={step['uses']}"
                if step.get("with"):
                    desc += f" with={json.dumps(step['with'], default=str)[:200]}"
            if step.get("run"):
                run = str(step["run"]).strip().replace("\n", " ; ")
                desc += f" run=`{run[:300]}`"
            flags = []
            if step.get("continue-on-error"):
                flags.append(f"continue-on-error={step['continue-on-error']}")
            if step.get("if") is not None:
                flags.append(f"if={step['if']}")
            if "secrets." in json.dumps(step, default=str):
                flags.append("uses secrets")
            if re.search(r"\b(echo|printf|print|cat)\b[^\n]*\$\{\{\s*secrets\.", str(step.get("run", ""))):
                flags.append("SECRET VALUE PRINTED in run script")
            if _EXPR_UNTRUSTED.search(str(step.get("run", ""))):
                flags.append("UNTRUSTED github.event input interpolated directly into run script")
            lines.append(f"    step {i}: {desc.strip()}" + (f"  [{'; '.join(flags)}]" if flags else ""))
    return "\n".join(lines)
