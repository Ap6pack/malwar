# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scheduled scanning API endpoints (issue #26)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScheduleCreateBody(BaseModel):
    name: str = Field(description="Human-readable name for the scheduled job")
    target_path: str = Field(description="File path or URL to scan")
    schedule: str = Field(description="Cron expression (5-field)")
    layers: list[str] = Field(
        default=["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"],
    )
    enabled: bool = True


class ScheduleUpdateBody(BaseModel):
    name: str | None = None
    target_path: str | None = None
    schedule: str | None = None
    layers: list[str] | None = None
    enabled: bool | None = None


class ScheduleResponse(BaseModel):
    job_id: str
    name: str
    target_path: str
    schedule: str
    layers: list[str]
    enabled: bool
    last_run: str | None
    next_run: str | None
    created_at: str


class JobRunResponse(BaseModel):
    run_id: str
    job_id: str
    scan_id: str | None
    status: str
    verdict: str | None
    risk_score: int | None
    error: str | None
    started_at: str
    completed_at: str | None


class ScheduleDetailResponse(ScheduleResponse):
    recent_runs: list[JobRunResponse] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _job_to_response(job) -> ScheduleResponse:
    return ScheduleResponse(
        job_id=job.job_id,
        name=job.name,
        target_path=job.target_path,
        schedule=job.schedule,
        layers=job.layers,
        enabled=job.enabled,
        last_run=job.last_run.isoformat() if job.last_run else None,
        next_run=job.next_run.isoformat() if job.next_run else None,
        created_at=job.created_at.isoformat(),
    )


def _run_to_response(run) -> JobRunResponse:
    return JobRunResponse(
        run_id=run.run_id,
        job_id=run.job_id,
        scan_id=run.scan_id,
        status=run.status,
        verdict=run.verdict,
        risk_score=run.risk_score,
        error=run.error,
        started_at=run.started_at.isoformat(),
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
    )


async def _get_store():
    from malwar.scheduler.store import JobStore
    from malwar.storage.database import get_db

    db = await get_db()
    return JobStore(db)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/schedules", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    body: ScheduleCreateBody,
    _api_key: str = Depends(require_api_key),
) -> ScheduleResponse:
    """Create a new scheduled scan job."""
    from malwar.scheduler.cron import CronParseError, next_run_from_cron
    from malwar.scheduler.jobs import ScanJob

    # Validate cron expression
    try:
        next_run = next_run_from_cron(body.schedule, datetime.now(UTC))
    except CronParseError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {exc}") from exc

    job = ScanJob(
        job_id=f"sched-{uuid.uuid4().hex[:12]}",
        name=body.name,
        target_path=body.target_path,
        schedule=body.schedule,
        layers=body.layers,
        enabled=body.enabled,
        next_run=next_run,
        created_at=datetime.now(UTC),
    )

    store = await _get_store()
    await store.create_job(job)

    return _job_to_response(job)


@router.get("/schedules", response_model=list[ScheduleResponse])
async def list_schedules(
    _api_key: str = Depends(require_api_key),
) -> list[ScheduleResponse]:
    """List all scheduled scan jobs."""
    store = await _get_store()
    jobs = await store.list_jobs()
    return [_job_to_response(j) for j in jobs]


@router.get("/schedules/{job_id}", response_model=ScheduleDetailResponse)
async def get_schedule(
    job_id: str,
    _api_key: str = Depends(require_api_key),
) -> ScheduleDetailResponse:
    """Get a scheduled job's details and recent runs."""
    store = await _get_store()
    job = await store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Schedule {job_id} not found")

    runs = await store.get_runs_for_job(job_id)

    resp = _job_to_response(job)
    return ScheduleDetailResponse(
        **resp.model_dump(),
        recent_runs=[_run_to_response(r) for r in runs],
    )


@router.put("/schedules/{job_id}", response_model=ScheduleResponse)
async def update_schedule(
    job_id: str,
    body: ScheduleUpdateBody,
    _api_key: str = Depends(require_api_key),
) -> ScheduleResponse:
    """Update a scheduled job's configuration."""
    from malwar.scheduler.cron import CronParseError, next_run_from_cron

    store = await _get_store()
    job = await store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Schedule {job_id} not found")

    if body.name is not None:
        job.name = body.name
    if body.target_path is not None:
        job.target_path = body.target_path
    if body.layers is not None:
        job.layers = body.layers
    if body.enabled is not None:
        job.enabled = body.enabled
    if body.schedule is not None:
        try:
            job.next_run = next_run_from_cron(body.schedule, datetime.now(UTC))
        except CronParseError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid cron expression: {exc}"
            ) from exc
        job.schedule = body.schedule

    await store.update_job(job)
    return _job_to_response(job)


@router.delete("/schedules/{job_id}", status_code=204)
async def delete_schedule(
    job_id: str,
    _api_key: str = Depends(require_api_key),
) -> None:
    """Delete a scheduled scan job."""
    store = await _get_store()
    deleted = await store.delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Schedule {job_id} not found")


@router.post("/schedules/{job_id}/run", response_model=JobRunResponse)
async def trigger_run(
    job_id: str,
    _api_key: str = Depends(require_api_key),
) -> JobRunResponse:
    """Trigger an immediate run of a scheduled job."""
    from malwar.scheduler.engine import SchedulerEngine

    store = await _get_store()
    job = await store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Schedule {job_id} not found")

    engine = SchedulerEngine(store)
    run = await engine.execute_job(job)
    return _run_to_response(run)
