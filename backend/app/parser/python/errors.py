"""Parser error definitions for the Python AST engine."""


class ParserError(Exception):
    """Base exception for all parser-related failures."""


class PythonSyntaxError(ParserError):
    """Raised when Python source cannot be parsed into an AST due to syntax invalidity."""

    def __init__(
        self,
        file_path: str,
        lineno: int | None,
        col_offset: int | None,
        message: str,
        text: str | None = None,
    ) -> None:
        self.file_path = file_path
        self.lineno = lineno
        self.col_offset = col_offset
        self.message = message
        self.text = text
        super().__init__(f"Syntax error in {file_path}:{lineno}:{col_offset}: {message}")


class PythonEncodingError(ParserError):
    """Raised when a Python source file cannot be decoded using expected or declared encoding."""

    def __init__(self, file_path: str, encoding: str, reason: str) -> None:
        self.file_path = file_path
        self.encoding = encoding
        self.reason = reason
        super().__init__(f"Encoding error in {file_path} using {encoding}: {reason}")


class PythonReadError(ParserError):
    """Raised when a source file cannot be read from the filesystem."""

    def __init__(self, file_path: str, reason: str) -> None:
        self.file_path = file_path
        self.reason = reason
        super().__init__(f"Failed to read file {file_path}: {reason}")


class UnsupportedLanguageError(ParserError):
    """Raised when the Python parser is invoked on a non-Python source file."""

    def __init__(self, file_path: str, language: str) -> None:
        self.file_path = file_path
        self.language = language
        super().__init__(
            f"Cannot parse file '{file_path}' with language '{language}' using Python AST parser"
        )
