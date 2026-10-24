"""DevOps repository auditing agent - command-line entry point.

Usage:
    python agent.py --repo https://github.com/owner/name --output report.json

Exit codes: 0 = audit completed and report written, 1 = fatal error, 2 = bad arguments.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from auditor.llm import LLMError, client_from_env
from auditor.loop import AuditAgent, Trace
from auditor.repo import RepoError, cleanup, clone, normalize_repo_url
from auditor.report import build_report, validate_report, write_json
from tools import RepoTools


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AI agent that audits a GitHub repository for DevOps best-practice violations.")
    p.add_argument("--repo", required=True, help="Public GitHub repository URL, e.g. https://github.com/owner/name")
    p.add_argument("--output", required=True, help="Path of the JSON report to write")
    p.add_argument("--trace", help="Where to write the tool-call trace (default: <output>.trace.jsonl)")
    p.add_argument("--max-steps", type=int, default=60, help="Maximum LLM turns (default 60)")
    p.add_argument("--max-minutes", type=float, default=20, help="Time budget in minutes (default 20)")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print errors")
    return p.parse_args(argv)


def main(argv=None, llm=None) -> int:
    args = parse_args(argv)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="replace")  # Windows consoles cannot print every character the LLM writes
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO, format="%(message)s", stream=sys.stderr)
    log = logging.getLogger("auditor")
    try:
        from dotenv import find_dotenv, load_dotenv

        # .env in the current directory first, then next to agent.py
        load_dotenv(find_dotenv(usecwd=True))
        load_dotenv(Path(__file__).resolve().parent / ".env")
    except ImportError:
        pass

    repo_info = None
    agent = None
    url = args.repo
    try:
        url = normalize_repo_url(args.repo)
        llm = llm or client_from_env()  # fail fast on missing credentials, before cloning
        log.info("Cloning %s ...", url)
        repo_info = clone(url)
        tools = RepoTools(repo_info.path)
        trace_path = args.trace or str(Path(args.output).with_suffix("")) + ".trace.jsonl"
        agent = AuditAgent(
            llm,
            tools,
            repo_info.summary(),
            max_steps=args.max_steps,
            max_seconds=args.max_minutes * 60,
            trace=Trace(trace_path),
        )
        violations = agent.run()
        report = build_report(url, violations)
        problems = validate_report(report)
        if problems:  # should never happen: findings are validated on entry
            raise RuntimeError("generated report is invalid: " + "; ".join(problems))
        write_json(args.output, report)
        log.info("Wrote %s (%d violation(s)). Trace: %s", args.output, len(violations), trace_path)
        return 0
    except (RepoError, LLMError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if agent is not None and agent.findings.active():
            # Keep what was confirmed before the failure, but still exit non-zero: the audit is incomplete.
            partial = args.output.removesuffix(".json") + ".partial.json"
            write_json(partial, build_report(url, agent.findings.active()))
            print(f"error: audit incomplete; {len(agent.findings.active())} confirmed violation(s) saved to {partial}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - last-resort guard so we always exit with a message
        print(f"error: unexpected failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if repo_info is not None:
            cleanup(repo_info.path)


if __name__ == "__main__":
    sys.exit(main())
