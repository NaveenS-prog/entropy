"""AST NodeVisitor for extracting normalized structural information from Python code."""

from __future__ import annotations

import ast
from typing import Any

from app.parser.python.models import (
    Assignment,
    CallExpression,
    ClassDefinition,
    ControlFlowConstruct,
    Decorator,
    ExceptionHandler,
    FunctionDefinition,
    ImportItem,
    Parameter,
    PythonModuleStructure,
    RaiseStatement,
    ReturnStatement,
    SourceLocation,
)


class PythonAstVisitor(ast.NodeVisitor):
    """Deterministic AST visitor extracting rich structural metadata from Python ASTs.

    Strictly static analysis: never executes code, imports modules, or evaluates expressions.
    """

    def __init__(self, file_path: str = "") -> None:
        self.file_path = file_path
        self.structure = PythonModuleStructure(file_path=file_path)

        # Scoping state
        self._scope_stack: list[str] = []
        self._class_stack: list[ClassDefinition] = []
        self._function_stack: list[FunctionDefinition] = []

    def extract(self, root: ast.Module) -> PythonModuleStructure:
        """Run extraction across the AST module and return the structured representation."""
        self.structure.docstring = ast.get_docstring(root)
        self.visit(root)
        return self.structure

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    def _current_function_name(self) -> str | None:
        return self._function_stack[-1].qualified_name if self._function_stack else None

    def _current_class_name(self) -> str | None:
        return self._class_stack[-1].qualified_name if self._class_stack else None

    def _build_qualified_name(self, name: str) -> str:
        if not self._scope_stack:
            return name
        return ".".join(self._scope_stack) + f".{name}"

    def _extract_decorators(self, decorator_list: list[ast.expr]) -> list[Decorator]:
        decorators: list[Decorator] = []
        for d in decorator_list:
            loc = SourceLocation.from_node(d)
            expr_str = ast.unparse(d)
            if isinstance(d, ast.Call):
                name = ast.unparse(d.func)
                args = [ast.unparse(a) for a in d.args]
                kwargs = {kw.arg: ast.unparse(kw.value) for kw in d.keywords if kw.arg}
            else:
                name = expr_str
                args = []
                kwargs = {}

            decorators.append(
                Decorator(
                    expression=expr_str,
                    name=name,
                    arguments=args,
                    keyword_arguments=kwargs,
                    location=loc,
                )
            )
        return decorators

    def _extract_parameters(self, args_node: ast.arguments) -> list[Parameter]:
        parameters: list[Parameter] = []

        # Positional defaults map to the rightmost positional arguments
        pos_args = args_node.posonlyargs + args_node.args
        num_pos_defaults = len(args_node.defaults)
        pos_defaults: list[ast.expr | None] = [None] * (len(pos_args) - num_pos_defaults) + list(
            args_node.defaults
        )

        # 1. Positional-only args
        for i, arg in enumerate(args_node.posonlyargs):
            default_val = pos_defaults[i]
            parameters.append(
                Parameter(
                    name=arg.arg,
                    annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                    default_value=ast.unparse(default_val) if default_val else None,
                    kind="posonly",
                    location=SourceLocation.from_node(arg),
                )
            )

        # 2. Standard args
        offset = len(args_node.posonlyargs)
        for i, arg in enumerate(args_node.args):
            default_val = pos_defaults[offset + i]
            parameters.append(
                Parameter(
                    name=arg.arg,
                    annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                    default_value=ast.unparse(default_val) if default_val else None,
                    kind="arg",
                    location=SourceLocation.from_node(arg),
                )
            )

        # 3. Vararg (*args)
        if args_node.vararg:
            parameters.append(
                Parameter(
                    name=args_node.vararg.arg,
                    annotation=ast.unparse(args_node.vararg.annotation)
                    if args_node.vararg.annotation
                    else None,
                    default_value=None,
                    kind="vararg",
                    location=SourceLocation.from_node(args_node.vararg),
                )
            )

        # 4. Keyword-only args
        for arg, kw_default in zip(args_node.kwonlyargs, args_node.kw_defaults, strict=False):
            parameters.append(
                Parameter(
                    name=arg.arg,
                    annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                    default_value=ast.unparse(kw_default) if kw_default else None,
                    kind="kwonly",
                    location=SourceLocation.from_node(arg),
                )
            )

        # 5. Kwarg (**kwargs)
        if args_node.kwarg:
            parameters.append(
                Parameter(
                    name=args_node.kwarg.arg,
                    annotation=ast.unparse(args_node.kwarg.annotation)
                    if args_node.kwarg.annotation
                    else None,
                    default_value=None,
                    kind="kwarg",
                    location=SourceLocation.from_node(args_node.kwarg),
                )
            )

        return parameters

    # -------------------------------------------------------------------------
    # Import Visitors
    # -------------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> Any:
        loc = SourceLocation.from_node(node)
        for alias in node.names:
            self.structure.imports.append(
                ImportItem(
                    module=alias.name,
                    name=alias.name,
                    alias=alias.asname,
                    is_from=False,
                    level=0,
                    location=loc,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        loc = SourceLocation.from_node(node)
        for alias in node.names:
            self.structure.imports.append(
                ImportItem(
                    module=node.module,
                    name=alias.name,
                    alias=alias.asname,
                    is_from=True,
                    level=node.level,
                    location=loc,
                )
            )
        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Class Visitor
    # -------------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        qname = self._build_qualified_name(node.name)
        loc = SourceLocation.from_node(node)
        decorators = self._extract_decorators(node.decorator_list)
        bases = [ast.unparse(b) for b in node.bases]
        docstring = ast.get_docstring(node)

        class_def = ClassDefinition(
            name=node.name,
            qualified_name=qname,
            file_path=self.file_path,
            location=loc,
            decorators=decorators,
            base_classes=bases,
            docstring=docstring,
        )

        if self._class_stack:
            self._class_stack[-1].nested_classes.append(qname)
        else:
            self.structure.classes.append(class_def)

        # Push scope
        self._class_stack.append(class_def)
        self._scope_stack.append(node.name)

        # Visit body
        for item in node.body:
            self.visit(item)

        # Pop scope
        self._scope_stack.pop()
        self._class_stack.pop()

    # -------------------------------------------------------------------------
    # Function Visitors
    # -------------------------------------------------------------------------

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> Any:
        is_method = len(self._class_stack) > 0 and len(self._function_stack) == 0
        qname = self._build_qualified_name(node.name)
        loc = SourceLocation.from_node(node)
        decorators = self._extract_decorators(node.decorator_list)
        params = self._extract_parameters(node.args)
        ret_annotation = ast.unparse(node.returns) if node.returns else None
        docstring = ast.get_docstring(node)
        stmt_count = len(node.body)

        func_def = FunctionDefinition(
            name=node.name,
            qualified_name=qname,
            file_path=self.file_path,
            location=loc,
            is_async=is_async,
            is_method=is_method,
            decorators=decorators,
            parameters=params,
            return_annotation=ret_annotation,
            docstring=docstring,
            statement_count=stmt_count,
        )

        if self._function_stack:
            # Nested function
            self._function_stack[-1].nested_functions.append(qname)
            self.structure.functions.append(func_def)
        elif self._class_stack:
            # Method inside class
            self._class_stack[-1].methods.append(func_def)
            self.structure.functions.append(func_def)
        else:
            # Module-level function
            self.structure.functions.append(func_def)

        # Push scope
        self._function_stack.append(func_def)
        scope_segment = f"{node.name}.<locals>" if self._function_stack[:-1] else node.name
        self._scope_stack.append(scope_segment)

        # Visit body
        for item in node.body:
            self.visit(item)

        # Pop scope
        self._scope_stack.pop()
        self._function_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._handle_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._handle_function(node, is_async=True)

    # -------------------------------------------------------------------------
    # Call Visitor
    # -------------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> Any:
        loc = SourceLocation.from_node(node)
        callable_name = ast.unparse(node.func)
        expr_str = ast.unparse(node)
        pos_args = [ast.unparse(a) for a in node.args]
        kw_args = [kw.arg for kw in node.keywords if kw.arg is not None]

        call_expr = CallExpression(
            callable_name=callable_name,
            expression=expr_str,
            arg_count=len(node.args) + len(node.keywords),
            positional_args=pos_args,
            keyword_args=kw_args,
            location=loc,
            enclosing_function=self._current_function_name(),
            enclosing_class=self._current_class_name(),
        )

        self.structure.all_calls.append(call_expr)
        if self._function_stack:
            self._function_stack[-1].calls.append(call_expr)

        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Exception Handling Visitors (Try / Raise)
    # -------------------------------------------------------------------------

    def visit_Try(self, node: ast.Try) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="try",
            location=loc,
            has_else=bool(node.orelse),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)

        for handler in node.handlers:
            h_loc = SourceLocation.from_node(handler)
            if handler.type is None:
                exc_types: list[str] = []
                is_bare = True
            elif isinstance(handler.type, ast.Tuple):
                exc_types = [ast.unparse(elt) for elt in handler.type.elts]
                is_bare = False
            else:
                exc_types = [ast.unparse(handler.type)]
                is_bare = False

            has_body = len(handler.body) > 0
            body_count = len(handler.body)
            has_pass_only = body_count == 1 and isinstance(handler.body[0], ast.Pass)

            exc_handler = ExceptionHandler(
                exception_types=exc_types,
                name=handler.name,
                is_bare=is_bare,
                has_body=has_body,
                body_statement_count=body_count,
                has_pass_only=has_pass_only,
                location=h_loc,
                enclosing_function=self._current_function_name(),
                enclosing_class=self._current_class_name(),
            )

            self.structure.all_handlers.append(exc_handler)
            if self._function_stack:
                self._function_stack[-1].handlers.append(exc_handler)

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> Any:
        loc = SourceLocation.from_node(node)
        exc_type: str | None = None
        if node.exc:
            if isinstance(node.exc, ast.Call):
                exc_type = ast.unparse(node.exc.func)
            else:
                exc_type = ast.unparse(node.exc)

        expr_str = ast.unparse(node.exc) if node.exc else None
        has_cause = node.cause is not None
        cause_type = ast.unparse(node.cause) if node.cause else None

        raise_stmt = RaiseStatement(
            exception_type=exc_type,
            expression=expr_str,
            has_cause=has_cause,
            cause_type=cause_type,
            location=loc,
            enclosing_function=self._current_function_name(),
            enclosing_class=self._current_class_name(),
        )

        self.structure.all_raises.append(raise_stmt)
        if self._function_stack:
            self._function_stack[-1].raises.append(raise_stmt)

        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Return Visitor
    # -------------------------------------------------------------------------

    def visit_Return(self, node: ast.Return) -> Any:
        loc = SourceLocation.from_node(node)
        has_val = node.value is not None
        val_repr = ast.unparse(node.value) if node.value else None

        ret_stmt = ReturnStatement(
            has_value=has_val,
            value_representation=val_repr,
            location=loc,
            enclosing_function=self._current_function_name(),
        )

        self.structure.all_returns.append(ret_stmt)
        if self._function_stack:
            self._function_stack[-1].returns.append(ret_stmt)

        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Assignment Visitors
    # -------------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> Any:
        loc = SourceLocation.from_node(node)
        targets = [ast.unparse(t) for t in node.targets]
        val_repr = ast.unparse(node.value)
        val_type = type(node.value).__name__

        assign = Assignment(
            targets=targets,
            value_representation=val_repr,
            value_type=val_type,
            is_augmented=False,
            operator=None,
            location=loc,
            enclosing_function=self._current_function_name(),
            enclosing_class=self._current_class_name(),
        )

        if self._function_stack:
            self._function_stack[-1].assignments.append(assign)
        elif self._class_stack:
            self._class_stack[-1].class_assignments.append(assign)
        else:
            self.structure.global_assignments.append(assign)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        loc = SourceLocation.from_node(node)
        targets = [ast.unparse(node.target)]
        val_repr = ast.unparse(node.value) if node.value else None
        val_type = type(node.value).__name__ if node.value else "Annotated"

        assign = Assignment(
            targets=targets,
            value_representation=val_repr,
            value_type=val_type,
            is_augmented=False,
            operator=None,
            location=loc,
            enclosing_function=self._current_function_name(),
            enclosing_class=self._current_class_name(),
        )

        if self._function_stack:
            self._function_stack[-1].assignments.append(assign)
        elif self._class_stack:
            self._class_stack[-1].class_assignments.append(assign)
        else:
            self.structure.global_assignments.append(assign)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        loc = SourceLocation.from_node(node)
        targets = [ast.unparse(node.target)]
        val_repr = ast.unparse(node.value)
        val_type = type(node.value).__name__
        op_name = type(node.op).__name__

        assign = Assignment(
            targets=targets,
            value_representation=val_repr,
            value_type=val_type,
            is_augmented=True,
            operator=op_name,
            location=loc,
            enclosing_function=self._current_function_name(),
            enclosing_class=self._current_class_name(),
        )

        if self._function_stack:
            self._function_stack[-1].assignments.append(assign)
        elif self._class_stack:
            self._class_stack[-1].class_assignments.append(assign)
        else:
            self.structure.global_assignments.append(assign)

        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Control Flow Visitors
    # -------------------------------------------------------------------------

    def visit_If(self, node: ast.If) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="if",
            location=loc,
            has_else=bool(node.orelse),
            condition_or_target=ast.unparse(node.test),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="for",
            location=loc,
            has_else=bool(node.orelse),
            is_async=False,
            condition_or_target=ast.unparse(node.target),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="for",
            location=loc,
            has_else=bool(node.orelse),
            is_async=True,
            condition_or_target=ast.unparse(node.target),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="while",
            location=loc,
            has_else=bool(node.orelse),
            condition_or_target=ast.unparse(node.test),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="with",
            location=loc,
            is_async=False,
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="with",
            location=loc,
            is_async=True,
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> Any:
        loc = SourceLocation.from_node(node)
        cf = ControlFlowConstruct(
            kind="assert",
            location=loc,
            condition_or_target=ast.unparse(node.test),
            enclosing_function=self._current_function_name(),
        )
        self.structure.all_control_flows.append(cf)
        if self._function_stack:
            self._function_stack[-1].control_flows.append(cf)
        self.generic_visit(node)
