"""JavaScript and TypeScript static analysis rules."""

from app.analyzers.jsts_rules.error_handling import JSEmptyCatchRule, JSSwallowedErrorFallbackRule
from app.analyzers.jsts_rules.input_validation import JSUnvalidatedInputRule
from app.analyzers.jsts_rules.logging_secrets import (
    JSHardcodedSecretRule,
    JSInsecureSecretFallbackRule,
    JSSensitiveLogRule,
)

__all__ = [
    "JSEmptyCatchRule",
    "JSHardcodedSecretRule",
    "JSInsecureSecretFallbackRule",
    "JSSensitiveLogRule",
    "JSSwallowedErrorFallbackRule",
    "JSUnvalidatedInputRule",
]
