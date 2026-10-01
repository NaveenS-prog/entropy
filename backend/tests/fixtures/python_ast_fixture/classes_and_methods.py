"""Test classes, methods, decorators, inheritance, and rich signatures."""

from abc import ABC, abstractmethod


def log_execution(level: str = "INFO"):
    def decorator(fn):
        return fn
    return decorator


def authenticated(fn):
    return fn


class BaseService(ABC):
    """Abstract base service definition."""

    @abstractmethod
    def health_check(self) -> bool:
        pass


@authenticated
class UserService(BaseService):
    """User account management service."""

    service_name = "user_svc"

    def __init__(self, db_client, timeout: int = 30) -> None:
        self.db = db_client
        self.timeout = timeout

    @log_execution(level="DEBUG")
    def health_check(self) -> bool:
        """Verify service connectivity."""
        return True

    @authenticated
    async def create_user(
        self,
        username: str,
        email: str,
        *tags: str,
        is_admin: bool = False,
        **extra_meta: str,
    ) -> dict:
        """Create a user asynchronously with diverse parameter kinds."""
        payload = {"username": username, "email": email, "is_admin": is_admin}
        return payload
