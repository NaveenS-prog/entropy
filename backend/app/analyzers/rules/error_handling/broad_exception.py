"""Backward compatibility adapter for ErrorHandlingDebtAnalyzer."""

from app.analyzers.rules.error_handling.analyzer import ErrorHandlingDebtAnalyzer
from app.analyzers.rules.error_handling.rules import (
    RULE_ERR_006_DEFERRED,
    BareExceptRule,
    BroadExceptionHandlerRule,
    EmptyExceptionHandlerRule,
    GenericFallbackReturnRule,
    SilentlySwallowedExceptionRule,
)

# Compatibility aliases for Phase 0 rules
RULE_ERR_001 = EmptyExceptionHandlerRule().definition
RULE_ERR_002 = BareExceptRule().definition

__all__ = [
    "BareExceptRule",
    "BroadExceptionHandlerRule",
    "EmptyExceptionHandlerRule",
    "ErrorHandlingDebtAnalyzer",
    "GenericFallbackReturnRule",
    "RULE_ERR_001",
    "RULE_ERR_002",
    "RULE_ERR_006_DEFERRED",
    "SilentlySwallowedExceptionRule",
]
