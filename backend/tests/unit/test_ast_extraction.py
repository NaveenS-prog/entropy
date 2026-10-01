"""Unit tests for AST structural extraction across classes, functions, calls, and exceptions."""

from app.parser.python.parser import PythonParser


def test_imports_extraction():
    parser = PythonParser()
    source = (
        "import os\n"
        "import sys as system\n"
        "from typing import List, Optional as Opt\n"
        "from .models import User\n"
        "from ..core.utils import helper\n"
    )
    unit = parser.parse_source(source, file_path="app.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    imports = unit.structure.imports
    assert len(imports) == 6

    # import os
    assert imports[0].module == "os"
    assert imports[0].name == "os"
    assert imports[0].alias is None
    assert imports[0].is_from is False
    assert imports[0].location.line_start == 1

    # import sys as system
    assert imports[1].module == "sys"
    assert imports[1].name == "sys"
    assert imports[1].alias == "system"
    assert imports[1].is_from is False
    assert imports[1].location.line_start == 2

    # from typing import List
    assert imports[2].module == "typing"
    assert imports[2].name == "List"
    assert imports[2].alias is None
    assert imports[2].is_from is True
    assert imports[2].level == 0
    assert imports[2].location.line_start == 3

    # from typing import Optional as Opt
    assert imports[3].name == "Optional"
    assert imports[3].alias == "Opt"

    # from .models import User
    assert imports[4].module == "models"
    assert imports[4].name == "User"
    assert imports[4].level == 1

    # from ..core.utils import helper
    assert imports[5].module == "core.utils"
    assert imports[5].name == "helper"
    assert imports[5].level == 2


def test_functions_and_parameters_extraction():
    parser = PythonParser()
    source = (
        "def compute(a: int, b: int = 10, *args: str, flag: bool = False, **kwargs: float) -> float:\n"
        "    '''Compute value.'''\n"
        "    return a + b\n"
        "\n"
        "async def fetch_data(url: str):\n"
        "    pass\n"
    )
    unit = parser.parse_source(source, file_path="service.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    funcs = unit.structure.functions
    assert len(funcs) == 2

    fn = funcs[0]
    assert fn.name == "compute"
    assert fn.qualified_name == "compute"
    assert fn.is_async is False
    assert fn.is_method is False
    assert fn.return_annotation == "float"
    assert fn.docstring == "Compute value."
    assert fn.location.line_start == 1

    # Check parameter kinds
    params = fn.parameters
    assert len(params) == 5
    assert params[0].name == "a" and params[0].kind == "arg" and params[0].annotation == "int"
    assert params[1].name == "b" and params[1].default_value == "10"
    assert params[2].name == "args" and params[2].kind == "vararg" and params[2].annotation == "str"
    assert params[3].name == "flag" and params[3].kind == "kwonly" and params[3].default_value == "False"
    assert params[4].name == "kwargs" and params[4].kind == "kwarg" and params[4].annotation == "float"

    # Async function
    async_fn = funcs[1]
    assert async_fn.name == "fetch_data"
    assert async_fn.is_async is True


def test_classes_and_methods_extraction():
    parser = PythonParser()
    source = (
        "@singleton\n"
        "class OrderService(BaseService, IOrder):\n"
        "    '''Order processing service.'''\n"
        "    timeout: int = 60\n"
        "\n"
        "    @authenticated\n"
        "    def create_order(self, item_id: str) -> bool:\n"
        "        return True\n"
    )
    unit = parser.parse_source(source, file_path="orders.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    classes = unit.structure.classes
    assert len(classes) == 1
    cls = classes[0]
    assert cls.name == "OrderService"
    assert cls.qualified_name == "OrderService"
    assert cls.base_classes == ["BaseService", "IOrder"]
    assert cls.docstring == "Order processing service."
    assert len(cls.decorators) == 1
    assert cls.decorators[0].name == "singleton"

    # Method inside class
    assert len(cls.methods) == 1
    method = cls.methods[0]
    assert method.name == "create_order"
    assert method.qualified_name == "OrderService.create_order"
    assert method.is_method is True
    assert len(method.decorators) == 1
    assert method.decorators[0].name == "authenticated"


def test_decorators_with_arguments():
    parser = PythonParser()
    source = (
        "@app.route('/api/v1/users', methods=['GET', 'POST'])\n"
        "@rate_limit(max_requests=100)\n"
        "@deprecated\n"
        "def get_users():\n"
        "    pass\n"
    )
    unit = parser.parse_source(source, file_path="routes.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    fn = unit.structure.functions[0]
    assert len(fn.decorators) == 3

    d1 = fn.decorators[0]
    assert d1.name == "app.route"
    assert len(d1.arguments) == 1
    assert d1.arguments[0] == "'/api/v1/users'"
    assert "methods" in d1.keyword_arguments

    d2 = fn.decorators[1]
    assert d2.name == "rate_limit"
    assert d2.keyword_arguments["max_requests"] == "100"

    d3 = fn.decorators[2]
    assert d3.name == "deprecated"
    assert len(d3.arguments) == 0


def test_calls_extraction():
    parser = PythonParser()
    source = (
        "def run_workflow():\n"
        "    init_context()\n"
        "    client.send_message('hello', timeout=5)\n"
    )
    unit = parser.parse_source(source, file_path="workflow.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    calls = unit.structure.all_calls
    assert len(calls) == 2

    c1 = calls[0]
    assert c1.callable_name == "init_context"
    assert c1.arg_count == 0
    assert c1.enclosing_function == "run_workflow"

    c2 = calls[1]
    assert c2.callable_name == "client.send_message"
    assert c2.arg_count == 2
    assert c2.positional_args == ["'hello'"]
    assert c2.keyword_args == ["timeout"]
    assert c2.enclosing_function == "run_workflow"


def test_exception_handling_and_raises_extraction():
    parser = PythonParser()
    source = (
        "def execute():\n"
        "    try:\n"
        "        do_work()\n"
        "    except (ConnectionError, TimeoutError) as net_err:\n"
        "        log_error(net_err)\n"
        "        raise SystemError('Network failed') from net_err\n"
        "    except ValueError:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n"
    )
    unit = parser.parse_source(source, file_path="worker.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    handlers = unit.structure.all_handlers
    assert len(handlers) == 3

    # Multi-exception handler
    h1 = handlers[0]
    assert h1.exception_types == ["ConnectionError", "TimeoutError"]
    assert h1.name == "net_err"
    assert h1.is_bare is False
    assert h1.has_pass_only is False
    assert h1.enclosing_function == "execute"

    # Specific exception with pass only
    h2 = handlers[1]
    assert h2.exception_types == ["ValueError"]
    assert h2.has_pass_only is True

    # Bare except
    h3 = handlers[2]
    assert h3.is_bare is True
    assert h3.has_pass_only is True

    # Raise with cause
    raises = unit.structure.all_raises
    assert len(raises) == 1
    r = raises[0]
    assert r.exception_type == "SystemError"
    assert r.has_cause is True
    assert r.cause_type == "net_err"
    assert r.enclosing_function == "execute"


def test_control_flow_and_loops():
    parser = PythonParser()
    source = (
        "def process(items):\n"
        "    if not items:\n"
        "        return\n"
        "    for item in items:\n"
        "        while item > 0:\n"
        "            item -= 1\n"
        "    assert len(items) > 0, 'Must have items'\n"
    )
    unit = parser.parse_source(source, file_path="flow.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    cfs = unit.structure.all_control_flows
    kinds = [cf.kind for cf in cfs]
    assert "if" in kinds
    assert "for" in kinds
    assert "while" in kinds
    assert "assert" in kinds


def test_nested_functions_and_inner_classes():
    parser = PythonParser()
    source = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def method(self):\n"
        "            def helper():\n"
        "                return 42\n"
        "            return helper()\n"
    )
    unit = parser.parse_source(source, file_path="nested.py")
    assert unit.is_valid is True
    assert unit.structure is not None

    classes = unit.structure.classes
    assert len(classes) == 1
    outer = classes[0]
    assert outer.name == "Outer"
    assert outer.nested_classes == ["Outer.Inner"]

    functions = unit.structure.functions
    qnames = [f.qualified_name for f in functions]
    assert "Outer.Inner.method" in qnames
    assert "Outer.Inner.method.helper" in qnames


def test_source_locations_accuracy():
    parser = PythonParser()
    source = (
        "# Line 1\n"
        "def target_func():\n"  # Line 2
        "    x = 10\n"          # Line 3
        "    return x\n"        # Line 4
    )
    unit = parser.parse_source(source, file_path="coords.py")
    assert unit.is_valid is True

    fn = unit.structure.functions[0]
    assert fn.location.line_start == 2
    assert fn.location.line_end == 4
    assert fn.location.col_offset == 0

    ret = unit.structure.all_returns[0]
    assert ret.location.line_start == 4
    assert ret.location.line_end == 4


def test_unicode_source_parsing():
    parser = PythonParser()
    source = (
        "π = 3.14159\n"
        "def calculate_area(r: float) -> float:\n"
        "    msg = 'Area: 🛡️'\n"
        "    return π * (r ** 2)\n"
    )
    unit = parser.parse_source(source, file_path="unicode.py")
    assert unit.is_valid is True
    assert len(unit.structure.functions) == 1
    assert unit.structure.functions[0].name == "calculate_area"
