from dataclasses import dataclass
import ast
from .repository import SourceFile


@dataclass
class ParseResult:
    tree: ast.AST | None
    error: str | None = None


def parse(source: SourceFile) -> ParseResult:
    if source.language == "python":
        try:
            return ParseResult(ast.parse(source.text))
        except SyntaxError as exc:
            return ParseResult(None, f"{exc.msg} at line {exc.lineno}")
    # Tree-sitter is intentionally optional; lexical analyzers remain safe and local.
    return ParseResult(None)
