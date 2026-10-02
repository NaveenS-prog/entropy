"""Code Duplication & Boilerplate Debt Analyzer package."""

from app.analyzers.duplication.analyzer import CodeDuplicationDebtAnalyzer
from app.analyzers.duplication.clustering import DuplicationDetector
from app.analyzers.duplication.models import DuplicationCluster, FunctionSignature
from app.analyzers.duplication.normalizer import ASTNormalizer, normalize_python_function
from app.analyzers.duplication.rules import ALL_DUPLICATION_RULES

__all__ = [
    "ALL_DUPLICATION_RULES",
    "ASTNormalizer",
    "CodeDuplicationDebtAnalyzer",
    "DuplicationCluster",
    "DuplicationDetector",
    "FunctionSignature",
    "normalize_python_function",
]
