"""JavaScript and TypeScript static analysis rules."""

from app.analyzers.jsts_rules.authentication import (
    JSDuplicatedAuthenticationRule,
    JSInconsistentAuthenticationRule,
    JSUnprotectedEndpointRule,
)
from app.analyzers.jsts_rules.authorization import (
    JSDuplicatedAuthorizationRule,
    JSInconsistentAuthorizationRule,
    JSMissingAuthorizationRule,
)
from app.analyzers.jsts_rules.detector import JSFrameworkRouteDetector
from app.analyzers.jsts_rules.error_handling import JSEmptyCatchRule, JSSwallowedErrorFallbackRule
from app.analyzers.jsts_rules.input_validation import JSUnvalidatedInputRule
from app.analyzers.jsts_rules.logging_secrets import (
    JSHardcodedSecretRule,
    JSInsecureSecretFallbackRule,
    JSSensitiveLogRule,
)

__all__ = [
    "JSDuplicatedAuthenticationRule",
    "JSDuplicatedAuthorizationRule",
    "JSEmptyCatchRule",
    "JSFrameworkRouteDetector",
    "JSHardcodedSecretRule",
    "JSInconsistentAuthenticationRule",
    "JSInconsistentAuthorizationRule",
    "JSInsecureSecretFallbackRule",
    "JSMissingAuthorizationRule",
    "JSSensitiveLogRule",
    "JSSwallowedErrorFallbackRule",
    "JSUnprotectedEndpointRule",
    "JSUnvalidatedInputRule",
]
