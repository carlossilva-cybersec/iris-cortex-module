"""Celery tasks following Cortex jobs, so the web UI never waits on Cortex.

* ``poll_execution`` re-schedules itself every ``poll_interval`` until the execution is final
  (success, failure, timeout, error). ``poll_once`` enforces ``job_timeout``; an attempt cap
  guarantees the chain stops even if polling keeps crashing.
* ``reconcile`` runs every minute (IRIS starts the worker with an embedded beat, ``-B``) and
  restarts the chain of executions whose task was lost (worker restart, broker outage).
"""
import os

from celery.signals import worker_process_init
from flask import current_app

from app import app as iris_app
from app import celery, db

POLL_TASK = "iris_cortex_module.poll_execution"
RECONCILE_TASK = "iris_cortex_module.reconcile"
MAX_ATTEMPTS = 5000


@worker_process_init.connect
def _fresh_db_pool_after_fork(**_kwargs):
    """IRIS' worker parent opens DB connections during post-init, then Celery forks its pool
    processes, which inherit the same sockets. Two processes talking over one PostgreSQL connection
    corrupts it ("error with status PGRES_TUPLES_OK and no message from the libpq"). Drop the
    inherited pool in each child without closing the parent's connections (SQLAlchemy's documented
    recipe for multiprocessing); new connections are opened lazily per process."""
    with iris_app.app_context():
        for engine in db.engines.values():
            engine.dispose(close=False)
        iris_app.logger.info(f"iris_cortex_module: DB pool reset in worker process {os.getpid()}")


@celery.task(name=POLL_TASK, bind=True, ignore_result=True)
def poll_execution(self, execution_id: int, attempt: int = 0):
    from iris_cortex_module.integration import service
    from iris_cortex_module.integration.config_store import load_settings

    try:
        final = service.poll_once(execution_id)
    except Exception:
        current_app.logger.exception(f"iris_cortex_module: polling execution #{execution_id} failed")
        final = False
    if final:
        return
    if attempt >= MAX_ATTEMPTS:
        current_app.logger.error(f"iris_cortex_module: giving up on execution #{execution_id} after {attempt} polls")
        return
    try:
        interval = load_settings().poll_interval
    except Exception:
        interval = 30
    poll_execution.apply_async((execution_id, attempt + 1), countdown=interval)


@celery.task(name=RECONCILE_TASK, ignore_result=True)
def reconcile():
    from iris_cortex_module.integration import service

    for execution_id in service.reconcile_stale():
        current_app.logger.info(f"iris_cortex_module: resuming lost polling of execution #{execution_id}")
        poll_execution.delay(execution_id)


def schedule_poll(execution_id: int, countdown: int) -> None:
    try:
        poll_execution.apply_async((execution_id, 0), countdown=countdown)
    except Exception:
        # Broker unavailable: the UI refresh and the reconciler will follow the job instead.
        current_app.logger.exception(f"iris_cortex_module: unable to queue polling of execution #{execution_id}")


def register_beat_schedule() -> None:
    schedule = dict(celery.conf.beat_schedule or {})
    schedule["iris_cortex_reconcile"] = {"task": RECONCILE_TASK, "schedule": 60.0}
    celery.conf.beat_schedule = schedule
