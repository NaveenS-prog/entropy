"""Unit tests for Phase 7 secret redaction before transmitting to AI providers."""

from app.ai.redaction import REDACTED_KEY, REDACTED_SECRET, redact_secrets


def test_redacts_stripe_secret():
    """Verify live and test Stripe keys are redacted."""
    token = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    text = f"stripe_key = '{token}'"
    redacted = redact_secrets(text)
    assert "sk_live_" not in redacted
    assert REDACTED_SECRET in redacted


def test_redacts_github_token():
    """Verify GitHub personal access tokens are redacted."""
    token = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    text = f"gh_pat = '{token}'"
    redacted = redact_secrets(text)
    assert "ghp_" not in redacted
    assert REDACTED_SECRET in redacted


def test_redacts_aws_key():
    """Verify AWS access key IDs are redacted."""
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"aws_access_key = '{token}'"
    redacted = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert REDACTED_SECRET in redacted


def test_redacts_sensitive_assignment():
    """Verify variable assignments with sensitive identifier names are redacted."""
    samples = [
        ("api_key = 'my-secret-value-12345'", "api_key = '[REDACTED_SECRET]'"),
        ("password = 'super_secret_password'", "password = '[REDACTED_SECRET]'"),
        ("client_secret: 'oauth_client_secret_xyz'", "client_secret: '[REDACTED_SECRET]'"),
        ("token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'", "token = '[REDACTED_SECRET]'"),
    ]
    for raw, expected in samples:
        result = redact_secrets(raw)
        assert result == expected
        assert REDACTED_SECRET in result
        assert "my-secret-value-12345" not in result
        assert "super_secret_password" not in result


def test_redacts_slack_token():
    """Verify Slack bot tokens are redacted."""
    token = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    text = f"slack_token = '{token}'"
    redacted = redact_secrets(text)
    assert "xoxb-" not in redacted
    assert REDACTED_SECRET in redacted


def test_redacts_private_key_block():
    """Verify RSA / OpenSSH private key blocks are replaced with REDACTED_PRIVATE_KEY."""
    text = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y3yJ...
    ...middle content...
    -----END RSA PRIVATE KEY-----
    """
    redacted = redact_secrets(text)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
    assert REDACTED_KEY in redacted


def test_redacts_google_api_key():
    """Verify Google AI / GCP API keys are redacted."""
    token = "AIzaSy" + "D-1234567890abcdefghijklmnopqrst"
    text = f"gemini_key = '{token}'"
    redacted = redact_secrets(text)
    assert "AIzaSy" not in redacted
    assert REDACTED_SECRET in redacted


def test_preserves_non_secret_code():
    """Verify benign source code lines without credentials remain intact."""
    clean_code = "def authenticate_user(username: str, is_admin: bool) -> bool:\n    return is_admin"
    assert redact_secrets(clean_code) == clean_code

