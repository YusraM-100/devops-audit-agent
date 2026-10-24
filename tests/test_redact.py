"""Secrets must never leave the tools in clear text."""

from auditor.redact import redact


def test_known_token_formats():
    for token in ["AKIA" + "Q" * 16, "ghp_" + "a" * 36, "sk-" + "b" * 40, "AIza" + "c" * 35, "xoxb-" + "1" * 20]:
        assert token not in redact(f"key: {token}")


def test_assignments_are_masked_but_names_kept():
    assert redact('password = "s3cretValue!"') == 'password = "[REDACTED]"'
    assert redact("DB_PASSWORD=hunter2hunter2") == "DB_PASSWORD=[REDACTED]"


def test_placeholders_and_references_are_kept():
    for text in [
        'api_key = "your-api-key-here"',
        "token = os.environ['TOKEN']",
        "password: ${{ secrets.DB_PASSWORD }}",
        "SECRET_KEY=changeme",
        "token = get_token()",
    ]:
        assert redact(text) == text


def test_url_credentials_and_private_keys():
    assert "pw123456" not in redact("postgres://admin:pw123456@db:5432/x")
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIabc" not in redact(key)
