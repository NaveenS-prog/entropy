"""Test control flow constructs, loops, with statements, asserts, and calls."""

import asyncio


def execute_pipeline(items: list[int]) -> int:
    """Execute pipeline processing with control flow."""
    total = 0

    if not items:
        return 0
    elif len(items) == 1:
        total = items[0]
    else:
        for x in items:
            if x % 2 == 0:
                total += x
        else:
            total += 1

    idx = 0
    while idx < 5:
        idx += 1
    else:
        log_info("Loop completed")

    with open("/dev/null") as f:
        data = f.read()
        assert len(data) == 0, "Buffer should be empty"

    return total


async def async_worker(queue: asyncio.Queue) -> None:
    async with asyncio.Lock():
        async for item in queue:
            process_item(item)


def log_info(msg: str) -> None:
    pass


def process_item(item: int) -> None:
    pass
