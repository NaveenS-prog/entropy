"""Test exception structures: try, except, finally, bare except, and raises."""


class PaymentGatewayError(Exception):
    pass


def process_payment(amount: float) -> bool:
    """Process a charge with explicit exception handling."""
    if amount <= 0:
        raise ValueError("Amount must be positive")

    try:
        charge_card(amount)
    except ConnectionError as e:
        log_error("Network down", exc=e)
        raise PaymentGatewayError("Service unavailable") from e
    except (KeyError, TypeError):
        log_warning("Malformed payload")
        return False
    except:
        # Bare except with pass only
        pass
    finally:
        cleanup_connection()

    return True


def charge_card(amount: float) -> None:
    pass


def log_error(msg: str, exc: Exception) -> None:
    pass


def log_warning(msg: str) -> None:
    pass


def cleanup_connection() -> None:
    pass
