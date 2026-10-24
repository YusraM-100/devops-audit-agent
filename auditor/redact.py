"""Secret redaction.

Every piece of text that leaves a tool (and therefore reaches the LLM, the
trace file, or the final report) goes through ``redact()``. The goal is that
the agent can still *see* that a secret exists ("API_KEY = '[REDACTED]'")
without the secret value itself ever being copied anywhere.
"""

from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED]"

# Well-known token formats. These are redacted wherever they appear.
_TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{16}"),  # AWS temporary key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),  # GitLab
    re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic style
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google API key
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"sk_live_[0-9A-Za-z]{20,}"),  # Stripe
    re.compile(r"rk_live_[0-9A-Za-z]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    re.DOTALL,
)

# Credentials embedded in URLs: scheme://user:password@host
_URL_CREDS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/\s@]+):(?P<pw>[^@/\s]+)@")

# name = "value" / name: value / NAME=value where name looks secret-ish.
_SECRET_NAME = r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|client[_-]?secret)"
_ASSIGNMENT = re.compile(
    r"(?P<key>[\w.-]*" + _SECRET_NAME + r"[\w.-]*)"
    r"(?P<sep>\s*[:=]\s*|\s*=>\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[^'\"\s,;)}#]{4,})"
    r"(?P=quote)",
    re.IGNORECASE,
)

# Values that are obviously not real secrets. We keep them visible because
# the agent needs them to tell a placeholder from a real credential.
_SAFE_VALUE = re.compile(
    r"^(?:\$\{\{.*|\$\{.*|\$[A-Z_]+|<.*>|%\(.*|\{\{.*|os\.environ.*|os\.getenv.*|getenv.*|env\(.*"
    r"|.*(?:your|example|changeme|change_me|placeholder|dummy|sample|xxxx|\*\*\*|redacted|todo|none|null|true|false).*)$",
    re.IGNORECASE,
)


def _looks_like_reference(key: str, value: str) -> bool:
    """Unquoted values such as ``password=user_password`` or ``token=get()`` are code, not secrets."""
    if not re.fullmatch(r"[A-Za-z_][\w.]*(?:[\[(].*)?", value):
        return False
    return (
        "." in value
        or "(" in value
        or "[" in value
        or value.lower() == key.lower().split(".")[-1]
        or re.fullmatch(r"[A-Z_][A-Z0-9_]*", value) is not None
        or re.fullmatch(r"[a-z]+(?:_[a-z]+)+", value) is not None
    )


def _mask_assignment(match: re.Match) -> str:
    value = match.group("value")
    if _SAFE_VALUE.match(value) or value.startswith(("os.", "settings.", "config.", "self.", "env.")):
        return match.group(0)
    if not match.group("quote") and _looks_like_reference(match.group("key"), value):
        return match.group(0)
    return f"{match.group('key')}{match.group('sep')}{match.group('quote')}{PLACEHOLDER}{match.group('quote')}"


def redact(text: str) -> str:
    """Return ``text`` with anything that looks like a secret value replaced."""
    if not text:
        return text
    text = _PRIVATE_KEY.sub("-----BEGIN PRIVATE KEY----- " + PLACEHOLDER + " -----END PRIVATE KEY-----", text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(PLACEHOLDER, text)
    text = _URL_CREDS.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{PLACEHOLDER}@", text)
    text = _ASSIGNMENT.sub(_mask_assignment, text)
    return text


def redact_obj(obj):
    """Recursively redact every string inside a JSON-like object."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
