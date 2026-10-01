"""API DTO schemas for analyzer and rule definitions."""

from pydantic import BaseModel

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage


class RuleSummaryResponse(BaseModel):
    rule_id: str
    category: DebtCategory
    title: str
    description: str
    default_severity: Severity
    default_confidence: Confidence
    languages: list[SupportedLanguage]
    impact_template: str
    recommendation_template: str


class AnalyzerSummaryResponse(BaseModel):
    analyzer_id: str
    name: str
    category: DebtCategory
    supported_languages: list[SupportedLanguage]
    rules: list[RuleSummaryResponse]
