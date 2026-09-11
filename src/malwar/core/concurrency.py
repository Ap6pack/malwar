"""Bounded concurrent execution over an iterable of work items.

``asyncio.gather(*(worker(x) for x in items))`` wraps every coroutine in a Task
immediately, so a semaphore *inside* the worker bounds how many run but not how
many exist. Over a 12,000-skill sweep that is 12,000 live Tasks holding ~16 MiB
to keep 8 of them busy.

:func:`run_bounded` inverts it: a fixed pool of workers pulls from a queue, so
the number of live Tasks is the concurrency limit rather than the input size.

Reported by @Nievesjyl in Ap6pack/malwar#57, and reproduced independently:

    n=12000  gather-all   tasks_alive=12001  peak_active=8   16,579 KiB
    n=12000  worker-pool  tasks_alive=9      peak_active=8      477 KiB
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeVar

T = TypeVar("T")


async def run_bounded(
    items: Iterable[T],
    worker: Callable[[T], Awaitable[None]],
    *,
    concurrency: int,
) -> None:
    """Await ``worker(item)`` for every item, at most ``concurrency`` at a time.

    Unlike ``gather`` with an internal semaphore, only ``concurrency`` Tasks
    exist at any moment, so memory is flat in the size of the input.

    Exception semantics match ``asyncio.gather`` without ``return_exceptions``:
    the first failure propagates. Items not yet started are dropped, and the
    other in-flight workers are cancelled rather than left running. Callers in
    this codebase catch inside their own worker so one bad skill cannot abort a
    sweep; this only covers a genuinely unexpected failure.

    Order is not preserved. Nothing here depends on it -- each worker writes to
    a dict keyed by slug -- and requiring it would mean holding results.
    """
    queue: asyncio.Queue[T] = asyncio.Queue()
    for item in items:
        queue.put_nowait(item)
    if queue.empty():
        return

    async def _pump() -> None:
        while True:
            try:
                item = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            await worker(item)

    pool = [asyncio.create_task(_pump()) for _ in range(max(1, concurrency))]
    try:
        await asyncio.gather(*pool)
    except BaseException:
        # Stop the rest of the pool instead of leaving workers running against
        # a sweep that is already failing.
        for task in pool:
            task.cancel()
        await asyncio.gather(*pool, return_exceptions=True)
        raise
