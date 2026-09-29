"""Execution / audit table owned by the module.

Registered on IRIS' metadata when the web extension loads (before post-init ``db.create_all()``),
so the table is created on first start. No foreign keys to IRIS tables: IRIS deletes cases,
alerts and users by deleting rows of known tables, and the audit trail must outlive them.
"""
from sqlalchemy import JSON, BigInteger, Boolean, Column, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from app import db

STATUS_PENDING = "pending"          # created in IRIS, not yet accepted by Cortex
STATUS_WAITING = "waiting"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"          # the Cortex job failed
STATUS_TIMEOUT = "timeout"          # still running after job_timeout
STATUS_ERROR = "error"              # IRIS could not submit or follow the job
FINAL_STATUSES = (STATUS_SUCCESS, STATUS_FAILURE, STATUS_TIMEOUT, STATUS_ERROR)

CORTEX_TO_LOCAL = {"Waiting": STATUS_WAITING, "InProgress": STATUS_IN_PROGRESS, "Success": STATUS_SUCCESS,
                   "Failure": STATUS_FAILURE, "Deleted": STATUS_ERROR}


class CortexExecution(db.Model):
    __tablename__ = "iris_cortex_execution"

    id = Column(BigInteger, primary_key=True)
    uuid = Column(UUID(as_uuid=True), nullable=False, unique=True)
    request_uuid = Column(UUID(as_uuid=True), unique=True)          # responders: idempotency key
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime)
    finished_at = Column(DateTime)
    next_poll_at = Column(DateTime)
    poll_count = Column(Integer, default=0)

    user_id = Column(BigInteger, nullable=False)
    user_login = Column(Text, nullable=False)
    client_ip = Column(Text)
    is_from_api = Column(Boolean, default=False)

    context_type = Column(String(16), nullable=False)               # case | alert
    context_id = Column(BigInteger, nullable=False)
    customer_id = Column(BigInteger)
    customer_name = Column(Text)

    object_kind = Column(String(16), nullable=False)                # ioc | evidence | file | case | alert
    object_id = Column(BigInteger, nullable=False)
    object_label = Column(Text)

    worker_type = Column(String(16), nullable=False)                # analyzer | responder
    worker_id = Column(Text, nullable=False)
    worker_name = Column(Text)
    worker_version = Column(Text)
    privileged = Column(Boolean, default=False)

    data_type = Column(Text, nullable=False)
    observable = Column(Text)                                       # value sent (file name for files)
    tlp = Column(Integer)
    pap = Column(Integer)
    parameters = Column(JSON)
    request_payload = Column(JSON)                                  # what was sent (responder entity included)

    cortex_url = Column(Text)
    cortex_job_id = Column(Text)
    cortex_status = Column(String(16))
    status = Column(String(16), nullable=False, default=STATUS_PENDING)

    verdict = Column(String(16))
    taxonomies = Column(JSON)
    highlights = Column(JSON)
    report = Column(JSON)
    report_truncated = Column(Boolean, default=False)
    artifacts = Column(JSON)
    operations = Column(JSON)
    imported = Column(JSON)

    error_message = Column(Text)
    error_detail = Column(Text)
    timeline_event_id = Column(BigInteger)

    __table_args__ = (
        Index("ix_iris_cortex_execution_context", "context_type", "context_id"),
        Index("ix_iris_cortex_execution_object", "object_kind", "object_id"),
        Index("ix_iris_cortex_execution_user_created", "user_id", "created_at"),
        Index("ix_iris_cortex_execution_status", "status"),
    )

    @property
    def is_final(self) -> bool:
        return self.status in FINAL_STATUSES

    def to_dict(self, include_report: bool = False) -> dict:
        def iso(value):
            return value.isoformat() if value else None

        data = {
            "id": self.id,
            "uuid": str(self.uuid),
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "finished_at": iso(self.finished_at),
            "user_login": self.user_login,
            "context_type": self.context_type,
            "context_id": self.context_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "object_label": self.object_label,
            "worker_type": self.worker_type,
            "worker_id": self.worker_id,
            "worker_name": self.worker_name,
            "worker_version": self.worker_version,
            "privileged": bool(self.privileged),
            "data_type": self.data_type,
            "observable": self.observable,
            "tlp": self.tlp,
            "pap": self.pap,
            "cortex_job_id": self.cortex_job_id,
            "cortex_status": self.cortex_status,
            "status": self.status,
            "final": self.is_final,
            "verdict": self.verdict,
            "taxonomies": self.taxonomies or [],
            "highlights": self.highlights or [],
            "artifacts": self.artifacts or [],
            "operations": self.operations or [],
            "imported": self.imported or [],
            "report_truncated": bool(self.report_truncated),
            "error_message": self.error_message,
        }
        if include_report:
            data["report"] = self.report
            data["error_detail"] = self.error_detail
            data["parameters"] = self.parameters
        return data
