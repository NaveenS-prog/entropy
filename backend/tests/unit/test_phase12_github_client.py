"""Unit tests for Phase 12 GitHub REST API client."""

from unittest.mock import MagicMock, patch

import pytest

from app.github.client import GitHubAPIError, GitHubClient


def test_client_headers_without_token():
    """Client headers include standard Accept and User-Agent without Authorization when no token."""
    client = GitHubClient(token=None, base_url="https://api.github.com")
    headers = client._get_headers()
    assert headers["Accept"] == "application/vnd.github+json"
    assert "Entropy" in headers["User-Agent"]
    assert "Authorization" not in headers


def test_client_headers_with_token():
    """Client headers include Bearer authorization when token is provided."""
    client = GitHubClient(token="mock_entropy_github_token_xyz", base_url="https://api.github.com")
    headers = client._get_headers()
    assert headers["Authorization"] == "Bearer mock_entropy_github_token_xyz"


@patch("httpx.Client.get")
def test_get_pull_request_success(mock_get):
    """Successfully parse PR response into GitHubPullRequestInfo."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.json.return_value = {
        "number": 42,
        "title": "Feature: Implement Secure Authentication",
        "html_url": "https://github.com/org/repo/pull/42",
        "base": {"ref": "main", "sha": "1111111111111111111111111111111111111111"},
        "head": {"ref": "feature/auth", "sha": "2222222222222222222222222222222222222222"},
    }
    mock_get.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    pr_info = client.get_pull_request("org", "repo", 42)

    assert pr_info is not None
    assert pr_info.number == 42
    assert pr_info.title == "Feature: Implement Secure Authentication"
    assert pr_info.base_sha == "1111111111111111111111111111111111111111"
    assert pr_info.head_sha == "2222222222222222222222222222222222222222"


@patch("httpx.Client.get")
def test_get_pull_request_not_found(mock_get):
    """PR 404 returns None gracefully without crashing."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.is_success = False
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    pr_info = client.get_pull_request("org", "repo", 999)
    assert pr_info is None


@patch("httpx.Client.get")
def test_get_pull_request_rate_limited(mock_get):
    """Rate limit response raises GitHubAPIError with rate_limited=True."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.is_success = False
    mock_resp.headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}
    mock_get.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    with pytest.raises(GitHubAPIError) as exc_info:
        client.get_pull_request("org", "repo", 42)
    assert exc_info.value.rate_limited is True


@patch("httpx.Client.post")
def test_create_check_run_success(mock_post):
    """Successfully creates Check Run and returns check_run_id."""
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.json.return_value = {"id": 884422}
    mock_post.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    check_run_id = client.create_check_run(
        owner="org",
        repo="repo",
        name="Entropy Test",
        head_sha="2222222222222222222222222222222222222222",
        status="in_progress",
    )
    assert check_run_id == 884422


@patch("httpx.Client.patch")
def test_update_check_run_success(mock_patch):
    """Successfully updates Check Run to completed neutral."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_patch.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    success = client.update_check_run(
        owner="org",
        repo="repo",
        check_run_id=884422,
        status="completed",
        conclusion="neutral",
    )
    assert success is True


@patch("httpx.Client.get")
def test_find_existing_comment(mock_get):
    """Identifies existing Entropy comment containing the HTML marker."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.json.return_value = [
        {"id": 101, "body": "Standard human comment"},
        {"id": 102, "body": "<!-- entropy-pr-report -->\n## Entropy Report\n..."},
    ]
    mock_get.return_value = mock_resp

    client = GitHubClient(token="mock_token")
    comment_id = client.find_existing_comment("org", "repo", 42)
    assert comment_id == 102
