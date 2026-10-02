"""Fixture containing non-route functions and classes.

None of these functions should be detected as web endpoints or produce security debt findings:
- CLI functions
- Background jobs / workers
- Internal utilities
- Plain calculation functions
- Unit test functions
"""

import click


@click.command()
@click.option("--count", default=1, help="Number of greetings.")
def run_cli_command(count):
    """CLI utility for system administration."""
    for _ in range(count):
        print("CLI executing")


def calculate_tax(subtotal: float, rate: float = 0.05) -> float:
    """Pure mathematical calculation function."""
    return subtotal * (1.0 + rate)


def format_user_display_name(first: str, last: str) -> str:
    """String manipulation helper."""
    return f"{first.strip().title()} {last.strip().title()}"


def _internal_crypto_hash(data: bytes) -> str:
    """Internal private hashing helper."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


class MetricCalculator:
    """Internal statistics processing class."""

    def compute_average(self, values: list[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)


def test_internal_logic():
    """Test function - must never be treated as web route."""
    assert calculate_tax(100.0) == 105.0
