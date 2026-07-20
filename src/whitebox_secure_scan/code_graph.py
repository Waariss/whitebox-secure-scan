"""Bounded, local symbol and call graph extraction.

This is intentionally not whole-program interprocedural taint analysis. It
connects obvious declarations, calls, and route handlers within the scanned
files so reviewers get better context without speculative edges.
"""

from dataclasses import dataclass, field
import re

from .repository import SourceFile


@dataclass
class Symbol:
    name: str
    file_path: str
    line: int
    kind: str
    calls: list[str] = field(default_factory=list)


@dataclass
class CodeGraph:
    symbols: list[Symbol] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)

    def symbol_at(self, file_path: str, line: int) -> Symbol | None:
        candidates = [
            item for item in self.symbols if item.file_path == file_path and item.line <= line
        ]
        return max(candidates, key=lambda item: item.line, default=None)

    def callers_of(self, name: str) -> list[str]:
        return sorted({symbol.name for symbol in self.symbols if name in symbol.calls})


FUNCTION_PATTERNS = (
    ("python", re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("), "function"),
    (
        "javascript",
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
        "function",
    ),
    (
        "typescript",
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
        "function",
    ),
    (
        "java",
        re.compile(
            r"\b(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"
        ),
        "method",
    ),
    ("go", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("), "function"),
)


CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
ROUTE_PATTERN = re.compile(
    r"(?:app|router|e|http\.HandleFunc)\s*[.]?\s*(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc)\s*[,(]\s*['\"]([^'\"]+)",
    re.IGNORECASE,
)


def _declaration(file: SourceFile, line: str, line_no: int) -> tuple[str, str] | None:
    for language, pattern, kind in FUNCTION_PATTERNS:
        if file.language != language:
            continue
        match = pattern.search(line)
        if match:
            return match.group(1), kind
    return None


def build_code_graph(files: list[SourceFile]) -> CodeGraph:
    graph = CodeGraph()
    for file in files:
        current: Symbol | None = None
        for line_no, line in enumerate(file.text.splitlines(), 1):
            declaration = _declaration(file, line, line_no)
            if declaration:
                current = Symbol(declaration[0], str(file.path), line_no, declaration[1])
                graph.symbols.append(current)
            if current:
                current.calls.extend(
                    name
                    for name in CALL_PATTERN.findall(line)
                    if name != current.name and name not in current.calls
                )
            route = ROUTE_PATTERN.search(line)
            if route:
                graph.routes.append(
                    {
                        "method": route.group(1).upper(),
                        "path": route.group(2),
                        "file": str(file.path),
                        "line": line_no,
                        "handler": current.name if current else None,
                    }
                )
    return graph


def enrich_route(route: dict, graph: CodeGraph) -> dict:
    enriched = dict(route)
    symbol = graph.symbol_at(route.get("file", ""), int(route.get("line", 1)))
    if symbol:
        enriched["handler"] = symbol.name
        enriched["related_callees"] = sorted(symbol.calls)
        enriched["related_callers"] = graph.callers_of(symbol.name)
        enriched["graph_scope"] = "same-file bounded call graph"
    else:
        enriched["related_callees"] = []
        enriched["related_callers"] = []
        enriched["graph_scope"] = "route syntax only"
    return enriched
