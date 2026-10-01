"""Error handling debt static analysis rules and analyzer."""

from app.analyzers.rules.error_handling.analyzer import ErrorHandlingDebtAnalyzer
from app.analyzers.rules.error_handling.rules import (
    RULE_ERR_006_DEFERRED,
    BareExceptRule,
    BroadExceptionHandlerRule,
    EmptyExceptionHandlerRule,
    GenericFallbackReturnRule,
    SilentlySwallowedExceptionRule,
)

__all__ = [
    "BareExceptRule",
    "BroadExceptionHandlerRule",
    "EmptyExceptionHandlerRule",
    "ErrorHandlingDebtAnalyzer",
    "GenericFallbackReturnRule",
    "RULE_ERR_006_DEFERRED",
    "SilentlySwallowedExceptionRule",
]
