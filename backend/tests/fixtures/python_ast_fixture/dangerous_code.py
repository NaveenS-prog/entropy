"""Test code containing execution traps to verify zero-code-execution guarantee."""

# If this file were imported or executed, it would raise RuntimeError immediately
def dangerous_decorator(*args, **kwargs):
    raise RuntimeError("SECURITY VIOLATION: Decorator was executed!")


@dangerous_decorator("exploit")
class DangerousClass:
    # If class body were evaluated, this would fail
    if False:
        pass


@dangerous_decorator
def dangerous_function():
    # If function were executed, this would fail
    raise RuntimeError("SECURITY VIOLATION: Function was executed!")
