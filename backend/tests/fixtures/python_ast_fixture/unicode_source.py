"""Module testing unicode identifiers and unicode string literals."""

import math

π = math.pi
Δ_threshold = 0.001


def calculate_circle_area(r: float) -> float:
    """Compute area using unicode constant π: π * r²."""
    greeting = "Hello, 世界! 🛡️"
    return π * (r**2)
