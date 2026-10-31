import logging

from fastapi import APIRouter, Header, HTTPException, Query, status

from app.ai.explainer import (
    DeterministicBaselineExplainer,
    FindingExplanation,
    RefactoringSuggestion,
)
from app.ai.provider import (
    AIProviderConfigError,
    AIProviderError,
    AIProviderMalformedResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    GeminiProvider,
    get_ai_provider,
)
from app.ai.service import AIDisabledError, FindingNotFoundError, ai_service
from app.core.config import settings
from app.models.domain.ai_explanation import AIExplanation
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding
from app.services.analysis_service import analysis_service

logger = logging.getLogger("entropy.api.findings")
router = APIRouter()
direct_router = APIRouter()
explainer = DeterministicBaselineExplainer()


@router.get("/{scan_id}/findings", response_model=list[Finding])
def get_findings_for_scan(
    scan_id: str,
    category: DebtCategory | None = Query(default=None, description="Filter by debt category"),
    severity: Severity | None = Query(default=None, description="Filter by finding severity"),
    rule_id: str | None = Query(
        default=None, description="Filter by specific rule ID (e.g. ENT-ERR-001)"
    ),
    file: str | None = Query(default=None, description="Filter by file path substring"),
    confidence: Confidence | None = Query(default=None, description="Filter by confidence"),
) -> list[Finding]:
    """Retrieve and filter deterministic architectural debt findings for a scan."""
    try:
        results = analysis_service.analyze_scan(
            scan_id=scan_id,
            category=category,
            severity=severity,
            rule_id=rule_id,
            file_filter=file,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    if confidence:
        results = [f for f in results if f.confidence == confidence]

    return results


@router.get("/{scan_id}/findings/{finding_id}", response_model=Finding)
def get_single_finding(scan_id: str, finding_id: str) -> Finding:
    """Retrieve a single finding by ID."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )
    return finding


@router.get("/{scan_id}/findings/{finding_id}/explain", response_model=FindingExplanation)
def explain_finding(scan_id: str, finding_id: str) -> FindingExplanation:
    """Retrieve a grounded architectural explanation for a finding."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.explain(finding)


@router.get("/{scan_id}/findings/{finding_id}/refactor", response_model=RefactoringSuggestion)
def suggest_refactor(scan_id: str, finding_id: str) -> RefactoringSuggestion:
    """Retrieve an architectural refactoring suggestion for a finding."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.suggest_refactor(finding)


async def _get_ai_explanation(
    finding_id: str,
    scan_id: str | None = None,
    gemini_api_key: str | None = None,
) -> AIExplanation:
    try:
        # Determine provider: prioritize injected provider (tests/overrides), then fake/gemini
        if ai_service._provider is not None:
            provider = ai_service._provider
        elif (settings.AI_PROVIDER == "fake" and not gemini_api_key) or (gemini_api_key and gemini_api_key.lower() in ("demo", "fake", "mock")):
            provider = get_ai_provider("fake", model_name="gemini-flash-lite-latest (Demo Mode)")
        else:
            provider = GeminiProvider(api_key=gemini_api_key) if gemini_api_key else GeminiProvider()

        return await ai_service.explain_finding(
            finding_id=finding_id,
            scan_id=scan_id,
            provider=provider,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except AIDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except AIProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Gemini API key is not configured. Please enter your Gemini API key in the website or set GEMINI_API_KEY in the environment: {exc}",
        ) from exc
    except AIProviderTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Gemini AI explanation request timed out",
        ) from exc
    except (AIProviderUnavailableError, AIProviderMalformedResponseError, AIProviderError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Gemini AI explanation temporarily unavailable: {exc}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error during AI explanation generation: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during explanation generation",
        ) from exc


@router.post("/{scan_id}/findings/{finding_id}/explanation", response_model=AIExplanation)
async def generate_scan_finding_explanation(
    scan_id: str,
    finding_id: str,
    x_gemini_api_key: str | None = Header(default=None, alias="X-Gemini-API-Key"),
) -> AIExplanation:
    """Generate or retrieve a cached AI-assisted architectural explanation (Gemini) for a finding in a scan."""
    return await _get_ai_explanation(
        finding_id=finding_id,
        scan_id=scan_id,
        gemini_api_key=x_gemini_api_key,
    )


@direct_router.post("/{finding_id}/explanation", response_model=AIExplanation)
async def generate_finding_explanation(
    finding_id: str,
    x_gemini_api_key: str | None = Header(default=None, alias="X-Gemini-API-Key"),
) -> AIExplanation:
    """Generate or retrieve a cached AI-assisted architectural explanation (Gemini) for a finding."""
    return await _get_ai_explanation(
        finding_id=finding_id,
        gemini_api_key=x_gemini_api_key,
    )
