"""C and C++ language adapters package."""

from app.analyzers.adapters.c_cpp.c_adapter import CLanguageAdapter
from app.analyzers.adapters.c_cpp.cpp_adapter import CppLanguageAdapter

__all__ = ["CLanguageAdapter", "CppLanguageAdapter"]
