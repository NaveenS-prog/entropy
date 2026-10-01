"""Core domain enumerations for Entropy."""

from enum import StrEnum


class DebtCategory(StrEnum):
    """The 7 foundational categories of Architectural Security Debt."""

    ERROR_HANDLING = "error_handling"
    AUTHENTICATION_CONSISTENCY = "authentication_consistency"
    AUTHORIZATION_CONSISTENCY = "authorization_consistency"
    INPUT_VALIDATION = "input_validation"
    LOGGING_AND_SECRETS = "logging_and_secrets"
    CODE_DUPLICATION = "code_duplication"
    ARCHITECTURAL_CONSISTENCY = "architectural_consistency"

    @property
    def display_name(self) -> str:
        names = {
            DebtCategory.ERROR_HANDLING: "Error Handling Debt",
            DebtCategory.AUTHENTICATION_CONSISTENCY: "Authentication Consistency Debt",
            DebtCategory.AUTHORIZATION_CONSISTENCY: "Authorization Consistency Debt",
            DebtCategory.INPUT_VALIDATION: "Input Validation Debt",
            DebtCategory.LOGGING_AND_SECRETS: "Logging & Secret-Handling Debt",
            DebtCategory.CODE_DUPLICATION: "Code Duplication / Boilerplate Debt",
            DebtCategory.ARCHITECTURAL_CONSISTENCY: "Architectural Consistency Debt",
        }
        return names.get(self, self.value)


class Severity(StrEnum):
    """Severity ratings for debt findings.

    Represents accumulation risk rather than active live exploitability.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Confidence that the detected pattern represents real debt."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DebtScoreTier(StrEnum):
    """Official score tiers defined by Entropy Product Specification (0-100)."""

    VERY_LOW = "very_low"  # 0 - 20
    LOW = "low"  # 21 - 40
    MODERATE = "moderate"  # 41 - 60
    HIGH = "high"  # 61 - 80
    VERY_HIGH = "very_high"  # 81 - 100

    @classmethod
    def from_score(cls, score: float) -> "DebtScoreTier":
        if score <= 20.0:
            return cls.VERY_LOW
        elif score <= 40.0:
            return cls.LOW
        elif score <= 60.0:
            return cls.MODERATE
        elif score <= 80.0:
            return cls.HIGH
        else:
            return cls.VERY_HIGH

    @property
    def label(self) -> str:
        labels = {
            DebtScoreTier.VERY_LOW: "Very Low Debt",
            DebtScoreTier.LOW: "Low Debt",
            DebtScoreTier.MODERATE: "Moderate Debt",
            DebtScoreTier.HIGH: "High Debt",
            DebtScoreTier.VERY_HIGH: "Very High Debt",
        }
        return labels.get(self, self.value)


class ScanStatus(StrEnum):
    """Lifecycle status of a scan."""

    PENDING = "pending"
    SCANNING = "scanning"
    QUEUED = "queued"
    INGESTING = "ingesting"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    SCORING = "scoring"
    COMPLETED = "completed"
    FAILED = "failed"


class SupportedLanguage(StrEnum):
    """Programming languages supported or recognized by Entropy."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    GO = "go"
    RUST = "rust"
    UNKNOWN = "unknown"
