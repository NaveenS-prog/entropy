"""Deterministic AST normalizer for structural code duplication detection.

Normalizes Python ASTs by:
- Anonymizing parameter and local variable names to canonical positions ($p1, $v1).
- Stripping docstrings and comments to ensure formatting/comment differences are ignored.
- Preserving semantic operators (Add, Sub, Mult, Div, Eq, NotEq) so x + y != x * y.
- Preserving numeric constants and literal semantics (e.g. 200 != 404).
- Preserving built-in functions and standard library exception classes.
- Extracting control-flow shapes and structural token sequences for similarity metrics.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from app.analyzers.duplication.models import FunctionSignature
from app.parser.python.models import SourceLocation

# Built-ins and well-known exceptions that retain their semantic identity
PRESERVED_NAMES = {
    "len", "range", "enumerate", "zip", "map", "filter", "sorted", "reversed",
    "int", "float", "str", "bool", "list", "dict", "set", "tuple", "bytes",
    "print", "isinstance", "issubclass", "hasattr", "getattr", "setattr", "delattr",
    "min", "max", "sum", "abs", "round", "any", "all",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError", "AttributeError",
    "RuntimeError", "FileNotFoundError", "PermissionError", "HTTPException",
    "True", "False", "None", "self", "cls",
}


class ASTNormalizer(ast.NodeTransformer):
    """Transforms an AST into a normalized canonical structure."""

    def __init__(self) -> None:
        super().__init__()
        self.param_map: dict[str, str] = {}
        self.var_map: dict[str, str] = {}
        self.param_counter = 1
        self.var_counter = 1
        self.control_flow: list[str] = []
        self.call_names: list[str] = []
        self.structural_tokens: list[str] = []
        self.operators: list[str] = []

    def normalize_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        source_code: str,
    ) -> FunctionSignature | None:
        """Create a normalized structural FunctionSignature from an AST function definition."""
        # 1. Register parameters in order
        for arg in func_node.args.posonlyargs + func_node.args.args + func_node.args.kwonlyargs:
            if arg.arg not in ("self", "cls"):
                self.param_map[arg.arg] = f"$p{self.param_counter}"
                self.param_counter += 1

        if func_node.args.vararg and func_node.args.vararg.arg not in ("self", "cls"):
            self.param_map[func_node.args.vararg.arg] = f"$p{self.param_counter}"
            self.param_counter += 1

        if func_node.args.kwarg and func_node.args.kwarg.arg not in ("self", "cls"):
            self.param_map[func_node.args.kwarg.arg] = f"$p{self.param_counter}"
            self.param_counter += 1

        # 2. Filter docstrings from body
        body = list(func_node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                body = body[1:]

        if not body:
            return None

        # Count statements (excluding docstring)
        statement_count = len(body)

        # 3. Create cloned node with cleaned body for transformation
        cloned_func = ast.FunctionDef(
            name="__fn__",
            args=func_node.args,
            body=body,
            decorator_list=[],
            returns=None,
        )

        # 4. Transform and collect structural tokens
        normalized_tree = self.visit(cloned_func)

        # Count total AST nodes in normalized function
        node_count = sum(1 for _ in ast.walk(normalized_tree))

        # 5. Produce canonical AST string and deterministic exact hash
        canonical_str = ast.dump(normalized_tree, annotate_fields=False, include_attributes=False)
        exact_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        # 6. Extract verbatim function source code snippet
        line_start = getattr(func_node, "lineno", 1)
        line_end = getattr(func_node, "end_lineno", line_start)
        lines = source_code.splitlines()
        func_source = "\n".join(lines[max(0, line_start - 1) : min(len(lines), line_end)])

        loc = SourceLocation(
            line_start=line_start,
            line_end=line_end,
            col_offset=getattr(func_node, "col_offset", None),
            end_col_offset=getattr(func_node, "end_col_offset", None),
        )

        return FunctionSignature(
            name=func_node.name,
            qualified_name=f"{file_path}:{func_node.name}",
            file_path=file_path,
            location=loc,
            statement_count=statement_count,
            node_count=node_count,
            exact_hash=exact_hash,
            structural_tokens=tuple(self.structural_tokens),
            control_flow_shape=tuple(self.control_flow),
            source_code=func_source,
            is_async=isinstance(func_node, ast.AsyncFunctionDef),
            is_method=any(arg.arg in ("self", "cls") for arg in func_node.args.args),
            parameter_count=len(self.param_map),
            call_names=tuple(self.call_names),
            operators=tuple(self.operators),
        )

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Anonymize variable names while preserving built-ins."""
        name = node.id
        if name in PRESERVED_NAMES:
            self.structural_tokens.append(f"Name:{name}")
            return node

        if name in self.param_map:
            anon_name = self.param_map[name]
        elif name in self.var_map:
            anon_name = self.var_map[name]
        else:
            if isinstance(node.ctx, (ast.Store, ast.Param)):
                anon_name = f"$v{self.var_counter}"
                self.var_counter += 1
                self.var_map[name] = anon_name
            else:
                anon_name = self.var_map.get(name, f"$v{self.var_counter}")

        self.structural_tokens.append("Name:anon")
        return ast.Name(id=anon_name, ctx=node.ctx)

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        """Preserve numbers and booleans, normalize arbitrary string literals."""
        val = node.value
        if isinstance(val, (int, float)):
            self.structural_tokens.append(f"Num:{val}")
            return node
        elif isinstance(val, bool):
            self.structural_tokens.append(f"Bool:{val}")
            return node
        elif val is None:
            self.structural_tokens.append("None")
            return node
        elif isinstance(val, str):
            # Short tokens / identifiers or keys are retained in structure, long arbitrary strings normalized
            if len(val) <= 12 and val.isidentifier():
                self.structural_tokens.append(f"StrId:{val}")
                return node
            self.structural_tokens.append("Str:norm")
            return ast.Constant(value="[STR]")
        return node

    def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
        op_name = type(node.op).__name__
        self.operators.append(op_name)
        self.structural_tokens.append(f"BinOp:{op_name}")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.UnaryOp:
        op_name = type(node.op).__name__
        self.operators.append(op_name)
        self.structural_tokens.append(f"UnaryOp:{op_name}")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Compare(self, node: ast.Compare) -> ast.Compare:
        ops = [type(op).__name__ for op in node.ops]
        self.operators.extend(ops)
        self.structural_tokens.append(f"Compare:{','.join(ops)}")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_If(self, node: ast.If) -> ast.If:
        self.control_flow.append("if")
        self.structural_tokens.append("ControlFlow:If")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_For(self, node: ast.For) -> ast.For:
        self.control_flow.append("for")
        self.structural_tokens.append("ControlFlow:For")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_While(self, node: ast.While) -> ast.While:
        self.control_flow.append("while")
        self.structural_tokens.append("ControlFlow:While")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Try(self, node: ast.Try) -> ast.Try:
        self.control_flow.append("try")
        self.structural_tokens.append("ControlFlow:Try")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        exc_name = ""
        if isinstance(node.type, ast.Name):
            exc_name = node.type.id
        self.control_flow.append(f"except:{exc_name or 'any'}")
        self.structural_tokens.append(f"Except:{exc_name or 'any'}")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Return(self, node: ast.Return) -> ast.Return:
        self.control_flow.append("return")
        self.structural_tokens.append("Return")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Raise(self, node: ast.Raise) -> ast.Raise:
        self.control_flow.append("raise")
        self.structural_tokens.append("Raise")
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Call(self, node: ast.Call) -> ast.Call:
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name:
            self.call_names.append(call_name)
            self.structural_tokens.append(f"Call:{call_name}")
        else:
            self.structural_tokens.append("Call:expr")
        return self.generic_visit(node)  # type: ignore[return-value]


def normalize_python_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    source_code: str,
) -> FunctionSignature | None:
    """Convenience helper to normalize a single function definition."""
    normalizer = ASTNormalizer()
    return normalizer.normalize_function(func_node, file_path, source_code)


def normalize_jsts_function(
    func: Any,
    file_path: str,
    source_code: str,
) -> FunctionSignature | None:
    """Create a normalized structural FunctionSignature from a JSFunction."""
    if func.statement_count < 2 or len(func.body_text.strip()) < 15:
        return None

    # Anonymize parameter names
    param_tokens = [f"$p{i+1}" for i in range(len(func.parameters))]

    # Structural tokens from function ast_signature or statement types
    tokens = list(func.ast_signature.split(":")) if func.ast_signature else ["FN"]
    # Control flow shape
    control_flow = [t for t in tokens if t in ("IF", "IF_", "FOR", "WHI", "SWI", "TRY", "RET", "THROW")]

    # Calls
    call_names = tuple(c.callee for c in func.calls)
    assign_types = tuple(a.value_type for a in func.assignments)
    return_types = tuple("fallback" if r.is_fallback_literal else "val" for r in func.returns)

    canonical_repr = (
        f"JSFN:params={len(param_tokens)}:"
        f"stmts={func.statement_count}:"
        f"tokens={':'.join(tokens)}:"
        f"calls={':'.join(call_names)}:"
        f"assigns={':'.join(assign_types)}:"
        f"returns={':'.join(return_types)}"
    )
    exact_hash = hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

    lines = source_code.splitlines(keepends=True)
    start = max(1, func.location.line_start)
    end = min(len(lines), func.location.line_end)
    snippet = "".join(lines[start - 1 : end])

    loc = SourceLocation(
        line_start=func.location.line_start,
        line_end=func.location.line_end,
        col_offset=func.location.col_start,
        end_col_offset=func.location.col_end,
    )

    node_count = getattr(func, "node_count", 0) or (len(tokens) + len(func.calls) + len(func.assignments))

    return FunctionSignature(
        name=func.name,
        qualified_name=func.qualified_name,
        file_path=file_path,
        location=loc,
        statement_count=func.statement_count,
        node_count=node_count,
        exact_hash=exact_hash,
        structural_tokens=tuple(tokens),
        control_flow_shape=tuple(control_flow),
        source_code=snippet,
        is_async=func.is_async,
        is_method=func.is_method,
        parameter_count=len(func.parameters),
        call_names=call_names,
        operators=(),
    )

