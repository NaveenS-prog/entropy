"""GitHub REST API client for Pull Request workflow and Check Run reporting."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings
from app.github.models import GitHubPullRequestInfo

logger = logging.getLogger("entropy.github.client")


class GitHubAPIError(Exception):
    """Raised when GitHub REST API returns an unexpected error response."""

    def __init__(self, status_code: int, message: str, rate_limited: bool = False) -> None:
        super().__init__(f"GitHub API Error {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.rate_limited = rate_limited


class GitHubClient:
    """Client for GitHub REST API with safe error handling, rate-limit awareness, and zero credential leakage."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.token = token or settings.GITHUB_TOKEN
        self.base_url = (base_url or settings.GITHUB_API_BASE_URL).rstrip("/")
        self.timeout = timeout or float(settings.GITHUB_TIMEOUT_SECONDS)

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Entropy-Architectural-Debt-Analyzer/0.1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _check_rate_limit(self, response: httpx.Response) -> None:
        remaining = response.headers.get("x-ratelimit-remaining")
        reset_epoch = response.headers.get("x-ratelimit-reset")
        if remaining == "0" or response.status_code == 429:
            logger.warning("GitHub API rate limit exhausted. Resets at epoch %s", reset_epoch)
            raise GitHubAPIError(
                status_code=response.status_code,
                message="GitHub API rate limit exceeded",
                rate_limited=True,
            )

    def get_pull_request(self, owner: str, repo: str, pr_number: int) -> GitHubPullRequestInfo | None:
        """Fetch Pull Request details including base SHA and head SHA."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                self._check_rate_limit(res)
                if res.status_code == 404:
                    logger.warning("Pull request #%s not found in %s/%s", pr_number, owner, repo)
                    return None
                if not res.is_success:
                    raise GitHubAPIError(res.status_code, res.text)

                data = res.json()
                return GitHubPullRequestInfo(
                    number=data["number"],
                    title=data["title"],
                    url=data.get("html_url"),
                    base_branch=data["base"]["ref"],
                    base_sha=data["base"]["sha"],
                    head_branch=data["head"]["ref"],
                    head_sha=data["head"]["sha"],
                )
        except httpx.TimeoutException as exc:
            logger.error("Timeout fetching PR #%s from %s/%s", pr_number, owner, repo)
            raise GitHubAPIError(504, "GitHub request timed out") from exc
        except httpx.RequestError as exc:
            logger.error("Network error communicating with GitHub API: %s", exc)
            raise GitHubAPIError(502, f"Network error: {exc}") from exc

    def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        status: str = "in_progress",
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
        details_url: str | None = None,
    ) -> int | None:
        """Create a GitHub Check Run for the given head commit SHA."""
        if not self.token:
            logger.debug("Skipping create_check_run: no GitHub credentials configured")
            return None

        url = f"{self.base_url}/repos/{owner}/{repo}/check-runs"
        payload: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        if conclusion:
            payload["conclusion"] = conclusion
        if output:
            payload["output"] = output
        if details_url:
            payload["details_url"] = details_url

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, headers=self._get_headers(), json=payload)
                self._check_rate_limit(res)
                if res.is_success:
                    check_run_id = res.json().get("id")
                    logger.info("Created Check Run %s for %s/%s at %s", check_run_id, owner, repo, head_sha[:8])
                    return check_run_id
                logger.warning("Failed to create Check Run (%d): %s", res.status_code, res.text)
                return None
        except Exception as exc:
            logger.warning("Failed to create Check Run on GitHub: %s", exc)
            return None

    def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str = "completed",
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
        details_url: str | None = None,
    ) -> bool:
        """Update an existing GitHub Check Run."""
        if not self.token or not check_run_id:
            return False

        url = f"{self.base_url}/repos/{owner}/{repo}/check-runs/{check_run_id}"
        payload: dict[str, Any] = {"status": status}
        if conclusion:
            payload["conclusion"] = conclusion
        if output:
            payload["output"] = output
        if details_url:
            payload["details_url"] = details_url

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.patch(url, headers=self._get_headers(), json=payload)
                self._check_rate_limit(res)
                if res.is_success:
                    logger.info("Updated Check Run %s to status=%s, conclusion=%s", check_run_id, status, conclusion)
                    return True
                logger.warning("Failed to update Check Run %s (%d): %s", check_run_id, res.status_code, res.text)
                return False
        except Exception as exc:
            logger.warning("Failed to update Check Run %s on GitHub: %s", check_run_id, exc)
            return False

    def find_existing_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        marker: str = "<!-- entropy-pr-report -->",
    ) -> int | None:
        """Find an existing Entropy PR comment by its embedded HTML marker."""
        if not self.token:
            return None

        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                self._check_rate_limit(res)
                if not res.is_success:
                    return None
                for comment in res.json():
                    if marker in comment.get("body", ""):
                        return comment["id"]
        except Exception as exc:
            logger.debug("Failed searching for existing PR comment: %s", exc)
        return None

    def create_or_update_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        comment_id: int | None = None,
    ) -> int | None:
        """Post a new PR comment or update an existing one to avoid notification spam."""
        if not self.token:
            logger.debug("Skipping PR comment: no GitHub credentials configured")
            return None

        try:
            with httpx.Client(timeout=self.timeout) as client:
                if comment_id:
                    # Update existing comment
                    url = f"{self.base_url}/repos/{owner}/{repo}/issues/comments/{comment_id}"
                    res = client.patch(url, headers=self._get_headers(), json={"body": body})
                    if res.is_success:
                        logger.info("Updated existing PR comment %s for PR #%s", comment_id, pr_number)
                        return comment_id
                # Create new comment
                url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
                res = client.post(url, headers=self._get_headers(), json={"body": body})
                if res.is_success:
                    new_id = res.json().get("id")
                    logger.info("Created new PR comment %s for PR #%s", new_id, pr_number)
                    return new_id
                logger.warning("Failed to post PR comment (%d): %s", res.status_code, res.text)
                return None
        except Exception as exc:
            logger.warning("Failed to post/update PR comment: %s", exc)
            return None
