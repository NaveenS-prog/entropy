"""Test deeply nested functions, inner classes, and qualified names."""


class OuterContainer:
    """Outer class holding inner classes and methods."""

    class InnerWorker:
        """Inner helper worker."""

        def compute(self, factor: int) -> int:
            def inner_closure(val: int) -> int:
                def deeply_nested(k: int) -> int:
                    return k * factor
                return deeply_nested(val)

            return inner_closure(10)


def top_level_builder():
    """Function containing a local function definition."""

    def local_builder():
        return "built"

    return local_builder()
