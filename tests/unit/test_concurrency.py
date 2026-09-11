"""Tests for bounded concurrent execution.

Ap6pack/malwar#57 reported that ``build_snapshot`` admitted one Task per skill
to ``asyncio.gather`` and bounded only how many *ran*, so live Tasks scaled
with the registry rather than with the concurrency limit. Reproduced
independently at the reporter's parameters (512 items, limit 8) and at the
sweep's real ceiling (12,000).

The load-bearing assertion is the second one in each pair: peak concurrency was
already correct under the old code, so a test that only checked it would have
passed against the bug.
"""

from __future__ import annotations

import asyncio

import pytest

from malwar.core.concurrency import run_bounded


async def _tracking_worker(limit_box: dict[str, int], gate: asyncio.Event):
    """Worker that records peak concurrency and blocks until released."""
    state = {"active": 0}

    async def worker(_item: int) -> None:
        state["active"] += 1
        limit_box["peak"] = max(limit_box["peak"], state["active"])
        await gate.wait()
        state["active"] -= 1

    return worker


class TestTaskCountIsBoundedByConcurrency:
    @pytest.mark.parametrize(("n", "concurrency"), [(512, 8), (12_000, 8), (100, 4)])
    async def test_live_tasks_track_the_limit_not_the_input(self, n, concurrency):
        box = {"peak": 0}
        gate = asyncio.Event()
        worker = await _tracking_worker(box, gate)

        before = len(asyncio.all_tasks())
        runner = asyncio.create_task(
            run_bounded(range(n), worker, concurrency=concurrency)
        )
        await asyncio.sleep(0.05)
        live = len(asyncio.all_tasks()) - before

        assert box["peak"] == concurrency, "concurrency limit not respected"
        # The regression itself: under gather-over-all this was n + 1.
        assert live <= concurrency + 2, (
            f"{live} live tasks for {n} items at concurrency {concurrency}; "
            "task count must not scale with input size"
        )

        gate.set()
        await runner


class TestEveryItemRuns:
    async def test_all_items_are_processed_exactly_once(self):
        seen: list[int] = []

        async def worker(item: int) -> None:
            await asyncio.sleep(0)
            seen.append(item)

        await run_bounded(range(250), worker, concurrency=7)
        assert sorted(seen) == list(range(250))
        assert len(seen) == len(set(seen)), "an item ran more than once"

    async def test_empty_input_is_a_no_op(self):
        async def worker(_item: int) -> None:  # pragma: no cover - must not run
            raise AssertionError("worker ran for an empty input")

        await run_bounded([], worker, concurrency=4)

    async def test_fewer_items_than_workers(self):
        seen: list[int] = []

        async def worker(item: int) -> None:
            seen.append(item)

        await run_bounded([1, 2], worker, concurrency=16)
        assert sorted(seen) == [1, 2]

    async def test_zero_concurrency_still_makes_progress(self):
        # A misconfigured limit must not deadlock a sweep.
        seen: list[int] = []

        async def worker(item: int) -> None:
            seen.append(item)

        await run_bounded([1, 2, 3], worker, concurrency=0)
        assert sorted(seen) == [1, 2, 3]


class TestFailureSemantics:
    async def test_first_exception_propagates(self):
        async def worker(item: int) -> None:
            if item == 3:
                raise ValueError("boom")
            await asyncio.sleep(0)

        with pytest.raises(ValueError, match="boom"):
            await run_bounded(range(20), worker, concurrency=4)

    async def test_pool_does_not_outlive_a_failure(self):
        # A worker still running after the call returned would keep hitting the
        # registry for a sweep that has already failed.
        running = {"count": 0}

        async def worker(item: int) -> None:
            if item == 0:
                raise ValueError("boom")
            running["count"] += 1
            await asyncio.sleep(5)
            running["count"] -= 1

        before = len(asyncio.all_tasks())
        with pytest.raises(ValueError):
            await run_bounded(range(50), worker, concurrency=8)
        await asyncio.sleep(0.05)
        assert len(asyncio.all_tasks()) <= before, "workers left running after failure"
