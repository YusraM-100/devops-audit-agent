"""Getting a safe, private copy of the repository to inspect.

The target repository is never modified: we always work on a fresh clone in
a temporary directory that is deleted when the audit finishes.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

GITHUB_URL = re.compile(r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")

# Environment for every git command: never prompt for credentials, never run
# LFS filters, never read the user's global/system git config.
GIT_ENV = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ASKPASS": "echo",
}


class RepoError(Exception):
    """Raised when the repository cannot be obtained."""


@dataclass
class RepoInfo:
    url: str
    path: Path
    default_branch: str | None = None
    branches: list[str] = field(default_factory=list)
    commit_count: int = 0

    def summary(self) -> str:
        return (
            f"Repository: {self.url}\n"
            f"Default branch: {self.default_branch or 'unknown'}\n"
            f"Branches: {', '.join(self.branches) or 'none'}\n"
            f"Commits on default branch: {self.commit_count}"
        )


def normalize_repo_url(value: str) -> str:
    """Validate a public GitHub URL (or a local path, for development)."""
    value = value.strip()
    if GITHUB_URL.match(value):
        return value.rstrip("/").removesuffix(".git")
    if Path(value).expanduser().is_dir():
        return str(Path(value).expanduser().resolve())
    raise RepoError(f"Not a valid public GitHub repository URL: {value!r}. Expected https://github.com/<owner>/<repo>")


def git(args: list[str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd,
        env=GIT_ENV,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
    )


def clone(repo: str, timeout: int = 300) -> RepoInfo:
    """Clone ``repo`` into a new temporary directory and describe it."""
    url = normalize_repo_url(repo)
    workdir = Path(tempfile.mkdtemp(prefix="devops-audit-"))
    target = workdir / "repo"
    try:
        if url.startswith("https://"):
            cmd = ["clone", "--quiet", "--no-recurse-submodules", url, str(target)]
        elif (Path(url) / ".git").exists():
            cmd = ["-c", "protocol.file.allow=always", "clone", "--quiet", "--no-local", "--no-recurse-submodules", url, str(target)]
        else:
            # A plain folder: copy it so we never touch the original.
            shutil.copytree(url, target, symlinks=True)
            return RepoInfo(url=url, path=target)
        result = git(cmd, cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        cleanup(workdir)
        raise RepoError(f"Cloning {url} timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        cleanup(workdir)
        raise RepoError("git is not installed or not on PATH") from exc
    if result.returncode != 0:
        cleanup(workdir)
        message = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown error"
        raise RepoError(f"Could not clone {url}: {message} (is the repository public and the URL correct?)")
    return _describe(url, target)


def _describe(url: str, path: Path) -> RepoInfo:
    info = RepoInfo(url=url, path=path)
    head = git(["symbolic-ref", "--short", "HEAD"], cwd=path)
    if head.returncode == 0:
        info.default_branch = head.stdout.strip()
    branches = git(["branch", "-r", "--format=%(refname:short)"], cwd=path)
    if branches.returncode == 0:
        info.branches = sorted({b.removeprefix("origin/") for b in branches.stdout.split() if b and b not in ("origin", "origin/HEAD")})
    count = git(["rev-list", "--count", "HEAD"], cwd=path)
    if count.returncode == 0 and count.stdout.strip().isdigit():
        info.commit_count = int(count.stdout.strip())
    return info


def cleanup(path: Path) -> None:
    """Delete the temporary clone (``path`` may be the repo or its parent)."""
    path = Path(path)
    if path.name == "repo" and path.parent.name.startswith("devops-audit-"):
        path = path.parent
    if path.name.startswith("devops-audit-"):
        shutil.rmtree(path, ignore_errors=True)
