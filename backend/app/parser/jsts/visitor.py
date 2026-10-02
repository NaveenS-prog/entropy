"""Tree-sitter AST visitor and structural extractor for JavaScript and TypeScript."""

from __future__ import annotations

import re
from typing import Any

from app.models.domain.enums import SupportedLanguage
from app.parser.jsts.models import (
    JSAssignment,
    JSCall,
    JSCatch,
    JSClass,
    JSExport,
    JSFunction,
    JSImport,
    JSReturn,
    JSRoute,
    JSSourceLocation,
    JSTSModuleStructure,
)

FALLBACK_LITERALS = {"null", "undefined", "false", "0", "''", '""', "[]", "{}"}

# Route methods to recognize
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "all", "use"}


class JSTSAstVisitor:
    """Traverses Tree-sitter syntax trees for JS/TS and extracts normalized structure."""

    def __init__(self, file_path: str, language: SupportedLanguage, source_bytes: bytes) -> None:
        self.file_path = file_path
        self.language = language
        self.source_bytes = source_bytes
        self.structure = JSTSModuleStructure(file_path=file_path, language=language)

    def extract(self, root_node: Any) -> JSTSModuleStructure:
        """Walk the AST root and populate the normalized module structure."""
        self._visit_node(root_node, enclosing_function=None, enclosing_class=None)
        self._detect_frameworks()
        return self.structure

    def _node_text(self, node: Any) -> str:
        """Extract UTF-8 text from node byte offsets."""
        if node is None:
            return ""
        try:
            sb = int(node.start_byte)
            eb = int(node.end_byte)
            if sb >= eb or sb < 0:
                return ""
            return self.source_bytes[sb:eb].decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _node_location(self, node: Any) -> JSSourceLocation:
        """Construct 1-indexed line, 0-indexed column source location."""
        sp = node.start_point
        ep = node.end_point
        return JSSourceLocation(
            line_start=sp[0] + 1,
            line_end=ep[0] + 1,
            col_start=sp[1],
            col_end=ep[1],
        )

    def _field(self, node: Any, field_name: str) -> Any | None:
        """Safely retrieve child by field name avoiding Tree-sitter C child_by_field_name bug."""
        if node is None:
            return None
        try:
            for i, child in enumerate(node.named_children):
                if node.field_name_for_named_child(i) == field_name:
                    return child
            for i, child in enumerate(node.children):
                if node.field_name_for_child(i) == field_name:
                    return child
        except Exception:
            pass
        return None

    def _visit_node(
        self,
        node: Any,
        enclosing_function: str | None = None,
        enclosing_class: str | None = None,
    ) -> None:
        """Recursive node visitor."""
        ntype = node.type

        # 1. Imports
        if ntype == "import_statement":
            self._handle_import_statement(node)
            return

        # 2. Exports
        if ntype in ("export_statement", "export_default_declaration"):
            self._handle_export_statement(node)

        # 3. Variable declarations / assignments
        if ntype in ("lexical_declaration", "variable_declaration"):
            self._handle_variable_declaration(node, enclosing_function)

        # 4. Class declarations
        if ntype == "class_declaration":
            self._handle_class(node)
            return

        # 5. Standalone functions
        if ntype == "function_declaration":
            self._handle_function_declaration(node, enclosing_class)
            return

        # 6. Try/Catch statements
        if ntype == "try_statement":
            self._handle_try_statement(node, enclosing_function)

        # 7. Call expressions
        if ntype == "call_expression":
            self._handle_call_expression(node, enclosing_function)

        # 8. Return statements
        if ntype == "return_statement":
            self._handle_return_statement(node, enclosing_function)

        # Recurse children
        for child in node.children:
            self._visit_node(
                child,
                enclosing_function=enclosing_function,
                enclosing_class=enclosing_class,
            )

    # -------------------------------------------------------------------------
    # Structural Handlers
    # -------------------------------------------------------------------------

    def _handle_import_statement(self, node: Any) -> None:
        """Extract import statement details."""
        loc = self._node_location(node)
        source_module = ""
        symbols: list[tuple[str, str | None]] = []
        is_default = False
        is_namespace = False

        for child in node.named_children:
            if child.type == "string":
                # Raw string module: 'express' or "./utils"
                raw = self._node_text(child).strip("'\"`")
                source_module = raw
            elif child.type == "import_clause":
                for clause_child in child.named_children:
                    if clause_child.type == "identifier":
                        # default import: import express from 'express'
                        is_default = True
                        symbols.append(("default", self._node_text(clause_child)))
                    elif clause_child.type == "named_imports":
                        for spec in clause_child.named_children:
                            if spec.type == "import_specifier":
                                name_node = self._field(spec, "name")
                                alias_node = self._field(spec, "alias")
                                name = self._node_text(name_node) if name_node else self._node_text(spec)
                                alias = self._node_text(alias_node) if alias_node else None
                                symbols.append((name, alias))
                    elif clause_child.type == "namespace_import":
                        is_namespace = True
                        name_node = self._field(clause_child, "name") or clause_child.named_children[-1]
                        symbols.append(("*", self._node_text(name_node)))

        if source_module:
            self.structure.imports.append(
                JSImport(
                    module=source_module,
                    symbols=symbols,
                    is_require=False,
                    is_default=is_default,
                    is_namespace=is_namespace,
                    location=loc,
                )
            )

    def _handle_export_statement(self, node: Any) -> None:
        """Extract export details."""
        loc = self._node_location(node)
        is_default = any(c.type == "default" for c in node.children) or node.type == "export_default_declaration"

        # Check for direct declaration
        for child in node.named_children:
            if child.type in ("function_declaration", "class_declaration"):
                name_node = self._field(child, "name")
                name = self._node_text(name_node) if name_node else "anonymous"
                self.structure.exports.append(JSExport(name=name, is_default=is_default, location=loc))
                return
            if child.type in ("lexical_declaration", "variable_declaration"):
                for decl in child.named_children:
                    name_node = self._field(decl, "name")
                    if name_node:
                        self.structure.exports.append(
                            JSExport(name=self._node_text(name_node), is_default=is_default, location=loc)
                        )
                return
            if child.type == "export_clause":
                for spec in child.named_children:
                    name_node = self._field(spec, "name") or spec
                    self.structure.exports.append(
                        JSExport(name=self._node_text(name_node), is_default=is_default, location=loc)
                    )
                return

        # Fallback
        self.structure.exports.append(JSExport(name="export", is_default=is_default, location=loc))

    def _handle_variable_declaration(self, node: Any, enclosing_function: str | None) -> list[JSAssignment]:
        """Extract variable declarations and detect require() or arrow functions."""
        created: list[JSAssignment] = []
        loc = self._node_location(node)
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue

            name_node = self._field(declarator, "name")
            value_node = self._field(declarator, "value")
            if not name_node:
                continue

            target_name = self._node_text(name_node)
            val_text = self._node_text(value_node) if value_node else ""
            val_type = value_node.type if value_node else "none"

            # Check require() imports: const x = require('./x')
            if value_node and value_node.type == "call_expression":
                callee_node = self._field(value_node, "function")
                if callee_node and self._node_text(callee_node) == "require":
                    args = self._field(value_node, "arguments")
                    req_module = ""
                    if args and args.named_children:
                        req_module = self._node_text(args.named_children[0]).strip("'\"`")
                    if req_module:
                        self.structure.imports.append(
                            JSImport(
                                module=req_module,
                                symbols=[(target_name, None)],
                                is_require=True,
                                is_default=True,
                                location=loc,
                            )
                        )

            # Check arrow / function expressions assigned to variables
            if value_node and value_node.type in ("arrow_function", "function_expression"):
                fn = self._extract_function(
                    node=value_node,
                    name=target_name,
                    enclosing_class=None,
                    is_arrow=(value_node.type == "arrow_function"),
                )
                self.structure.functions.append(fn)

            # Check environment variable access: process.env.SECRET || 'fallback'
            is_env = "process.env" in val_text
            env_var_name = None
            fallback_text = None
            if is_env:
                match = re.search(r"process\.env(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])", val_text)
                if match:
                    env_var_name = match.group(1) or match.group(2)
                if "||" in val_text or "??" in val_text:
                    parts = re.split(r"\|\||\?\?", val_text, maxsplit=1)
                    if len(parts) > 1:
                        fallback_text = parts[1].strip()

            assign = JSAssignment(
                target=target_name,
                value_text=val_text,
                value_type=val_type,
                is_env_access=is_env,
                env_var_name=env_var_name,
                fallback_text=fallback_text,
                location=loc,
                enclosing_function=enclosing_function,
            )
            self.structure.all_assignments.append(assign)
            created.append(assign)
        return created

    def _handle_class(self, node: Any) -> None:
        """Extract class definition and its methods."""
        loc = self._node_location(node)
        name_node = self._field(node, "name")
        class_name = self._node_text(name_node) if name_node else "AnonymousClass"

        # Superclass
        base_classes: list[str] = []
        for child in node.named_children:
            if child.type == "class_heritage":
                base_classes.append(self._node_text(child).replace("extends", "").strip())

        # Decorators
        decorators = self._extract_decorators(node)

        # Methods
        methods: list[JSFunction] = []
        body_node = self._field(node, "body")
        if body_node:
            for item in body_node.named_children:
                if item.type == "method_definition":
                    m_name_node = self._field(item, "name")
                    m_name = self._node_text(m_name_node) if m_name_node else "anonymous"
                    m_fn = self._extract_function(
                        node=item,
                        name=m_name,
                        enclosing_class=class_name,
                        is_method=True,
                    )
                    methods.append(m_fn)
                    self.structure.functions.append(m_fn)
                elif item.type == "field_definition":
                    f_name_node = self._field(item, "property") or self._field(item, "name")
                    val_node = self._field(item, "value")
                    if val_node and val_node.type in ("arrow_function", "function_expression"):
                        f_name = self._node_text(f_name_node) if f_name_node else "anonymous"
                        f_fn = self._extract_function(
                            node=val_node,
                            name=f_name,
                            enclosing_class=class_name,
                            is_method=True,
                        )
                        methods.append(f_fn)
                        self.structure.functions.append(f_fn)

        cls = JSClass(
            name=class_name,
            file_path=self.file_path,
            location=loc,
            base_classes=base_classes,
            decorators=decorators,
            methods=methods,
        )
        self.structure.classes.append(cls)

    def _handle_function_declaration(self, node: Any, enclosing_class: str | None) -> None:
        """Extract a standard function declaration."""
        name_node = self._field(node, "name")
        name = self._node_text(name_node) if name_node else "anonymous"
        fn = self._extract_function(
            node=node,
            name=name,
            enclosing_class=enclosing_class,
            is_method=False,
        )
        self.structure.functions.append(fn)

    def _extract_function(
        self,
        node: Any,
        name: str,
        enclosing_class: str | None = None,
        is_arrow: bool = False,
        is_method: bool = False,
    ) -> JSFunction:
        """Construct normalized JSFunction with statements, calls, handlers, returns."""
        loc = self._node_location(node)
        qname = f"{enclosing_class}.{name}" if enclosing_class else name
        is_async = any(c.type == "async" for c in node.children) or self._node_text(node).startswith("async")

        # Parameters
        params: list[str] = []
        params_node = self._field(node, "parameters")
        if params_node:
            for p in params_node.named_children:
                p_text = self._node_text(p)
                # Clean identifier name from type annotations: (x: string) -> x
                if ":" in p_text:
                    p_text = p_text.split(":", 1)[0].strip()
                if "=" in p_text:
                    p_text = p_text.split("=", 1)[0].strip()
                params.append(p_text)

        decorators = self._extract_decorators(node)

        # Body inspection
        body_node = self._field(node, "body")
        body_text = self._node_text(body_node) if body_node else ""
        statement_count = len(body_node.named_children) if body_node and body_node.type == "statement_block" else 1
        node_count = self._count_nodes(node)

        # Collect internal calls, handlers, returns
        fn_calls: list[JSCall] = []
        fn_handlers: list[JSCatch] = []
        fn_returns: list[JSReturn] = []
        fn_assigns: list[JSAssignment] = []
        structural_tokens: list[str] = []

        if body_node:
            self._inspect_function_body(
                body_node,
                enclosing_name=qname,
                calls=fn_calls,
                handlers=fn_handlers,
                returns=fn_returns,
                assigns=fn_assigns,
                tokens=structural_tokens,
            )

        # Duplication signature
        ast_signature = ":".join(structural_tokens) if structural_tokens else f"FN:{statement_count}"

        return JSFunction(
            name=name,
            qualified_name=qname,
            file_path=self.file_path,
            location=loc,
            is_async=is_async,
            is_arrow=is_arrow,
            is_method=is_method,
            parameters=params,
            statement_count=statement_count,
            node_count=node_count,
            enclosing_class=enclosing_class,
            calls=fn_calls,
            handlers=fn_handlers,
            returns=fn_returns,
            assignments=fn_assigns,
            decorators=decorators,
            body_text=body_text,
            ast_signature=ast_signature,
        )

    def _count_nodes(self, node: Any) -> int:
        """Count all descendant AST nodes in a subtree."""
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count

    def _inspect_function_body(
        self,
        node: Any,
        enclosing_name: str,
        calls: list[JSCall],
        handlers: list[JSCatch],
        returns: list[JSReturn],
        assigns: list[JSAssignment],
        tokens: list[str],
    ) -> None:
        """Deep inspection of statements within a function body for metrics and rules."""
        ntype = node.type

        # Structural tokens for duplication normalization
        if ntype in ("if_statement", "for_statement", "for_in_statement", "while_statement", "switch_statement"):
            tokens.append(ntype[:3].upper())
        elif ntype == "try_statement":
            tokens.append("TRY")
        elif ntype in ("lexical_declaration", "variable_declaration"):
            tokens.append("ASSIGN")
            new_assigns = self._handle_variable_declaration(node, enclosing_name)
            assigns.extend(new_assigns)
        elif ntype == "assignment_expression":
            tokens.append("ASSIGN")
        elif ntype == "return_statement":
            tokens.append("RET")
            ret = self._extract_return(node, enclosing_name)
            returns.append(ret)
            self.structure.all_returns.append(ret)
        elif ntype == "throw_statement":
            tokens.append("THROW")
        elif ntype == "call_expression":
            tokens.append("CALL")
            call = self._extract_call(node, enclosing_name)
            calls.append(call)
            self.structure.all_calls.append(call)
            self._check_route(call)

        if ntype == "try_statement":
            for child in node.named_children:
                if child.type == "catch_clause":
                    catch_obj = self._extract_catch(child, enclosing_name)
                    handlers.append(catch_obj)
                    self.structure.all_handlers.append(catch_obj)

        # Recurse children (skip nested function definitions for this function's scope)
        for child in node.children:
            if child.type not in ("function_declaration", "arrow_function", "function_expression"):
                self._inspect_function_body(
                    child,
                    enclosing_name=enclosing_name,
                    calls=calls,
                    handlers=handlers,
                    returns=returns,
                    assigns=assigns,
                    tokens=tokens,
                )

    def _handle_try_statement(self, node: Any, enclosing_function: str | None) -> None:
        """Direct try-statement handler."""
        for child in node.named_children:
            if child.type == "catch_clause":
                catch_obj = self._extract_catch(child, enclosing_function)
                # Only add if not already added by enclosing function inspection
                if not any(h.location == catch_obj.location for h in self.structure.all_handlers):
                    self.structure.all_handlers.append(catch_obj)

    def _extract_catch(self, catch_node: Any, enclosing_function: str | None) -> JSCatch:
        """Extract catch clause details, empty check, logging, re-throw, and fallback return."""
        loc = self._node_location(catch_node)
        param_node = self._field(catch_node, "parameter")
        param_name = self._node_text(param_node) if param_node else None

        body_node = self._field(catch_node, "body")
        has_body = body_node is not None
        statements = (
            [c for c in body_node.named_children if c.type != "comment"]
            if body_node and body_node.type == "statement_block"
            else []
        )
        statement_count = len(statements)
        is_empty = statement_count == 0

        # Comments inside catch block
        has_comment = False
        comment_text = None
        if body_node:
            for child in body_node.children:
                if child.type == "comment":
                    has_comment = True
                    comment_text = self._node_text(child).strip()
                    break

        # Re-throw check
        catch_text = self._node_text(catch_node)
        has_rethrow = "throw " in catch_text or "throw;" in catch_text

        # Logging check
        has_logging = any(
            log_marker in catch_text
            for log_marker in (
                "console.error",
                "console.warn",
                "console.log",
                "logger.error",
                "log.error",
                "logger.warn",
                "log.warn",
            )
        )

        # Fallback return check
        returns_fallback = False
        fallback_value = None
        for s in statements:
            if s.type == "return_statement":
                ret_val = self._field(s, "value") or (s.named_children[0] if s.named_children else None)
                val_str = self._node_text(ret_val).strip() if ret_val else "undefined"
                if val_str in FALLBACK_LITERALS or not ret_val:
                    returns_fallback = True
                    fallback_value = val_str

        return JSCatch(
            param_name=param_name,
            has_body=has_body,
            statement_count=statement_count,
            is_empty=is_empty,
            has_rethrow=has_rethrow,
            has_logging=has_logging,
            returns_fallback=returns_fallback,
            fallback_value=fallback_value,
            has_comment=has_comment,
            comment_text=comment_text,
            location=loc,
            enclosing_function=enclosing_function,
        )

    def _handle_call_expression(self, node: Any, enclosing_function: str | None) -> None:
        """Direct call-expression handler."""
        call = self._extract_call(node, enclosing_function)
        if not any(c.location == call.location for c in self.structure.all_calls):
            self.structure.all_calls.append(call)
            self._check_route(call)

    def _extract_call(self, call_node: Any, enclosing_function: str | None) -> JSCall:
        """Extract callee, caller object, method name, and arguments from call node."""
        loc = self._node_location(call_node)
        fn_node = self._field(call_node, "function")
        callee = self._node_text(fn_node) if fn_node else ""

        caller_object = None
        method_name = None
        if fn_node and fn_node.type == "member_expression":
            obj_node = self._field(fn_node, "object")
            prop_node = self._field(fn_node, "property")
            if obj_node:
                caller_object = self._node_text(obj_node)
            if prop_node:
                method_name = self._node_text(prop_node)
        elif "." in callee:
            parts = callee.split(".")
            caller_object = ".".join(parts[:-1])
            method_name = parts[-1]

        # Arguments
        args_list: list[str] = []
        args_node = self._field(call_node, "arguments")
        if args_node:
            for a in args_node.named_children:
                args_list.append(self._node_text(a))

        return JSCall(
            callee=callee,
            caller_object=caller_object,
            method_name=method_name,
            arguments=args_list,
            location=loc,
            enclosing_function=enclosing_function,
        )

    def _handle_return_statement(self, node: Any, enclosing_function: str | None) -> None:
        """Direct return statement handler."""
        ret = self._extract_return(node, enclosing_function)
        if not any(r.location == ret.location for r in self.structure.all_returns):
            self.structure.all_returns.append(ret)

    def _extract_return(self, node: Any, enclosing_function: str | None) -> JSReturn:
        """Extract return statement value and fallback status."""
        loc = self._node_location(node)
        val_node = self._field(node, "value") or (node.named_children[0] if node.named_children else None)
        val_text = self._node_text(val_node).strip() if val_node else None
        is_fallback = val_text is None or val_text in FALLBACK_LITERALS

        return JSReturn(
            value_text=val_text,
            is_fallback_literal=is_fallback,
            location=loc,
            enclosing_function=enclosing_function,
        )

    def _extract_decorators(self, node: Any) -> list[str]:
        """Extract decorator expressions from class or method."""
        decs: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                decs.append(self._node_text(child).lstrip("@").strip())
        return decs

    def _check_route(self, call: JSCall) -> None:
        """Check if a call represents an Express or Fastify route definition."""
        if not call.caller_object or not call.method_name:
            return

        method = call.method_name.lower()
        if method not in HTTP_METHODS:
            return

        # Check caller object: app, router, server, fastify, etc.
        obj = call.caller_object.lower()
        is_route_caller = any(k in obj for k in ("app", "router", "server", "fastify", "route"))
        if not is_route_caller:
            return

        if not call.arguments:
            return

        route_path = call.arguments[0].strip("'\"`")
        if not (route_path.startswith("/") or route_path == "*"):
            return

        framework = "fastify" if "fastify" in obj else "express"
        middleware: list[str] = []
        handler_name = None

        if len(call.arguments) > 1:
            for arg in call.arguments[1:-1]:
                middleware.append(arg)
            handler_name = call.arguments[-1]

        self.structure.routes.append(
            JSRoute(
                framework=framework,
                http_method=method.upper(),
                path=route_path,
                handler_name=handler_name,
                middleware=middleware,
                location=call.location,
            )
        )

    def _detect_frameworks(self) -> None:
        """Infer active frameworks from static indicators."""
        # 1. Imports
        for imp in self.structure.imports:
            mod = imp.module.lower()
            if "express" in mod:
                self.structure.frameworks.add("express")
            if "fastify" in mod:
                self.structure.frameworks.add("fastify")
            if "@nestjs" in mod:
                self.structure.frameworks.add("nestjs")
            if "next" in mod or mod.startswith("next/"):
                self.structure.frameworks.add("nextjs")
            if "react" in mod:
                self.structure.frameworks.add("react")

        # 2. Routes
        if any(r.framework == "express" for r in self.structure.routes):
            self.structure.frameworks.add("express")
        if any(r.framework == "fastify" for r in self.structure.routes):
            self.structure.frameworks.add("fastify")

        # 3. Decorators
        for cls in self.structure.classes:
            for d in cls.decorators:
                if any(nest_dec in d for nest_dec in ("Controller", "Injectable", "Module")):
                    self.structure.frameworks.add("nestjs")

        # 4. Next.js App / Pages file patterns
        norm_path = self.file_path.replace("\\", "/")
        if any(p in norm_path for p in ("app/api/", "pages/api/", "app/page.", "app/layout.")):
            self.structure.frameworks.add("nextjs")

        # 5. JSX / TSX
        if self.file_path.endswith((".jsx", ".tsx")):
            self.structure.frameworks.add("react")
