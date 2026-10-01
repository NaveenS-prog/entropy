"""Endpoints for querying registered analyzers and static analysis rules."""

from fastapi import APIRouter

from app.analyzers.registry import default_registry
from app.schemas.analyzer_schemas import AnalyzerSummaryResponse, RuleSummaryResponse

router = APIRouter()


@router.get("", response_model=list[AnalyzerSummaryResponse], summary="List Registered Analyzers")
def list_analyzers() -> list[AnalyzerSummaryResponse]:
    """Retrieve all active static analyzers and their rules."""
    result: list[AnalyzerSummaryResponse] = []
    for analyzer in default_registry.get_all():
        rule_dtos = [
            RuleSummaryResponse(
                rule_id=r.rule_id,
                category=r.category,
                title=r.title,
                description=r.description,
                default_severity=r.default_severity,
                default_confidence=r.default_confidence,
                languages=r.languages,
                impact_template=r.impact_template,
                recommendation_template=r.recommendation_template,
            )
            for r in analyzer.rules
        ]
        result.append(
            AnalyzerSummaryResponse(
                analyzer_id=analyzer.analyzer_id,
                name=analyzer.name,
                category=analyzer.category,
                supported_languages=list(analyzer.supported_languages),
                rules=rule_dtos,
            )
        )
    return result


@router.get("/rules", response_model=list[RuleSummaryResponse], summary="List Analysis Rules")
def list_rules() -> list[RuleSummaryResponse]:
    """Retrieve all declared static analysis rules across all analyzers."""
    return [
        RuleSummaryResponse(
            rule_id=r.rule_id,
            category=r.category,
            title=r.title,
            description=r.description,
            default_severity=r.default_severity,
            default_confidence=r.default_confidence,
            languages=r.languages,
            impact_template=r.impact_template,
            recommendation_template=r.recommendation_template,
        )
        for r in default_registry.list_rules()
    ]
