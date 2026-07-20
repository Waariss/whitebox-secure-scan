"""Local parser capability detection with safe lexical fallback.

Optional Tree-sitter support is deliberately additive. The scanner never
downloads grammars during a scan and continues with its conservative lexical
analyzers when the optional package is unavailable or cannot parse a file.
"""

from dataclasses import dataclass
import ast
from typing import Any

from .repository import SourceFile


TREE_SITTER_LANGUAGES = {
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
}


@dataclass
class ParseResult:
    tree: Any | None
    error: str | None = None
    parser_used: str = "none"
    syntax_node_type: str | None = None
    node_count: int = 0


def _count_nodes(node: Any) -> int:
    count = 0
    stack = [node]
    while stack:
        current = stack.pop()
        count += 1
        children = getattr(current, "children", ())
        stack.extend(children)
    return count


def _tree_sitter_parse(source: SourceFile) -> ParseResult | None:
    language = TREE_SITTER_LANGUAGES.get(source.language)
    if not language:
        return None
    try:
        from tree_sitter_languages import get_parser  # type: ignore[import-not-found]

        parser = get_parser(language)
        tree = parser.parse(source.text.encode("utf-8", errors="replace"))
    except ImportError:
        return None
    except Exception as exc:  # optional parser versions have incompatible APIs
        return ParseResult(None, f"optional parser failure: {exc}", "tree-sitter")
    root = tree.root_node
    return ParseResult(
        tree,
        None if not root.has_error else "syntax errors reported by optional parser",
        f"tree-sitter.{language}",
        root.type,
        _count_nodes(root),
    )


def parse(source: SourceFile) -> ParseResult:
    if source.language == "python":
        try:
            tree = ast.parse(source.text)
            return ParseResult(tree, parser_used="python.ast", syntax_node_type="Module")
        except SyntaxError as exc:
            return ParseResult(None, f"{exc.msg} at line {exc.lineno}", "python.ast")
    parsed = _tree_sitter_parse(source)
    if parsed is not None:
        return parsed
    return ParseResult(None, parser_used="lexical-fallback")


def parser_capabilities() -> dict[str, Any]:
    """Report available local parsers without importing or downloading code."""
    try:
        import tree_sitter_languages

        available = True
        version = getattr(tree_sitter_languages, "__version__", None)
    except ImportError:
        available = False
        version = None
    return {
        "python_ast": True,
        "tree_sitter": available,
        "tree_sitter_version": version,
        "languages": sorted(TREE_SITTER_LANGUAGES),
        "fallback": "structured lexical analysis",
    }
