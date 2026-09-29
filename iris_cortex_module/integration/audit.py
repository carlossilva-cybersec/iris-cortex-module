"""Timeline, alert history, activity feed and the IOC "Cortex" tab.

These functions run in the web process AND in the Celery worker (job completion), where there is
no request and no current_user: every write uses the execution's user id explicitly instead of
IRIS helpers that read current_user.
"""
import datetime
import json
from typing import Optional

from flask import current_app
from sqlalchemy.orm.attributes import flag_modified

from app import db
from app.datamgmt.case.case_events_db import save_event_category
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field
from app.datamgmt.states import update_timeline_state
from app.models import CaseEventsIoc, CasesEvent, EventCategory, Ioc, UserActivity
from app.models.alerts import Alert

from iris_cortex_module import MODULE_PACKAGE_NAME
from iris_cortex_module.core.results import render_ioc_tab_html, tlp_name
from iris_cortex_module.integration.models import STATUS_SUCCESS, CortexExecution

IOC_TAB = "Cortex"
IOC_TAB_FIELD = "Resultados"


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def record_activity(user_id: int, message: str, case_id: Optional[int] = None, display: bool = True,
                    from_api: bool = False) -> None:
    ua = UserActivity()
    ua.user_id = user_id
    ua.case_id = case_id
    ua.activity_date = _now()
    ua.activity_desc = message[:1].upper() + message[1:]
    ua.user_input = False
    ua.display_in_ui = display
    ua.is_from_api = from_api
    db.session.add(ua)
    db.session.commit()
    current_app.logger.info(f"iris_cortex_module :: user #{user_id} :: case {case_id} :: {message}")


def _history_entry(obj, user_id: int, login: str, action: str) -> None:
    history = obj.modification_history if isinstance(obj.modification_history, dict) else {}
    history[str(_now().timestamp())] = {"user": login, "user_id": user_id, "action": action}
    obj.modification_history = history
    flag_modified(obj, "modification_history")


def _event_lines(e: CortexExecution) -> str:
    worker_label = "Analyzer" if e.worker_type == "analyzer" else "Responder"
    lines = [
        f"{worker_label}: {e.worker_name} {e.worker_version or ''}".rstrip(),
        f"Observable: {e.observable or e.object_label}",
        f"Type: {e.data_type}",
        f"TLP: {tlp_name(e.tlp)}",
        f"Status: {e.status}",
    ]
    if e.verdict:
        lines.append(f"Verdict: {e.verdict}")
    if e.taxonomies:
        lines.append("Taxonomies: " + "; ".join(f"{t['namespace']}:{t['predicate']}={t['value']} ({t['level']})"
                                                for t in e.taxonomies[:10]))
    if e.error_message:
        lines.append(f"Error: {e.error_message}")
    lines += [
        f"Job ID: {e.cortex_job_id or '-'}",
        f"Executed by: {e.user_login}",
        f"Timestamp: {(e.finished_at or e.created_at).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Audit record: #{e.id}",
    ]
    return "\n".join(lines)


def _add_case_timeline_event(e: CortexExecution) -> None:
    title = "Cortex Analyzer executed" if e.worker_type == "analyzer" else "Cortex Responder executed"
    when = e.finished_at or _now()
    event = CasesEvent()
    event.case_id = e.context_id
    event.event_title = f"{title}: {e.worker_name} on {e.observable or e.object_label}"[:250]
    event.event_source = MODULE_PACKAGE_NAME
    event.event_content = _event_lines(e)
    event.event_raw = json.dumps(e.to_dict(), ensure_ascii=False, default=str)[:100000]
    event.event_date = when
    event.event_date_wtz = when
    event.event_tz = "+00:00"
    event.event_added = _now()
    event.event_in_graph = False
    event.event_in_summary = False
    event.event_tags = f"cortex,{e.worker_type}"
    event.event_color = "#f25961" if e.verdict == "malicious" else None
    event.user_id = e.user_id
    _history_entry(event, e.user_id, e.user_login, "created")
    db.session.add(event)
    update_timeline_state(caseid=e.context_id, userid=e.user_id)
    db.session.commit()

    category = EventCategory.query.filter(EventCategory.name == "Unspecified").first()
    if category is not None:
        save_event_category(event.event_id, category.id)
    if e.object_kind == "ioc":
        link = CaseEventsIoc()
        link.event_id = event.event_id
        link.ioc_id = e.object_id
        link.case_id = e.context_id
        db.session.add(link)
    e.timeline_event_id = event.event_id
    db.session.commit()


def _update_ioc_tab(e: CortexExecution) -> None:
    """Latest final execution per analyzer for this IOC, rendered in the IOC's Cortex tab."""
    ioc = Ioc.query.filter(Ioc.ioc_id == e.object_id).first()
    if ioc is None:
        return
    rows = (CortexExecution.query.filter(CortexExecution.object_kind == "ioc",
                                         CortexExecution.object_id == e.object_id,
                                         CortexExecution.worker_type == "analyzer",
                                         CortexExecution.finished_at.isnot(None))
            .order_by(CortexExecution.finished_at.desc()).limit(100).all())
    latest = {}
    for row in rows:
        latest.setdefault(row.worker_name, row)
    entries = [{"worker_name": r.worker_name, "finished_at": r.finished_at.isoformat() if r.finished_at else "",
                "status": r.status, "verdict": r.verdict, "taxonomies": r.taxonomies or [],
                "user_login": r.user_login} for r in latest.values()]
    add_tab_attribute_field(ioc, IOC_TAB, IOC_TAB_FIELD, "html", render_ioc_tab_html(entries))
    db.session.commit()


def record_completion(e: CortexExecution, add_timeline_event: bool, write_ioc_tab: bool) -> None:
    """Called once, when an execution reaches a final status. Best effort: never raises."""
    try:
        if e.context_type == "case":
            if add_timeline_event:
                _add_case_timeline_event(e)
        else:
            alert = Alert.query.filter(Alert.alert_id == e.context_id).first()
            if alert is not None:
                verb = "analyzer" if e.worker_type == "analyzer" else "responder"
                _history_entry(alert, e.user_id, e.user_login,
                               f"Cortex {verb} {e.worker_name} on {e.observable or e.object_label}: {e.status}"
                               f"{' (' + e.verdict + ')' if e.verdict else ''} (audit #{e.id})")
                db.session.commit()
        if write_ioc_tab and e.object_kind == "ioc" and e.worker_type == "analyzer":
            _update_ioc_tab(e)
        record_activity(e.user_id, f"cortex {e.worker_type} {e.worker_name} on "
                                   f"\"{e.observable or e.object_label}\" finished: {e.status} (audit #{e.id})",
                        case_id=e.context_id if e.context_type == "case" else None)
    except Exception:
        db.session.rollback()
        current_app.logger.exception(f"iris_cortex_module: execution #{e.id} finished but audit update failed")


def record_object_change(e: CortexExecution, message: str, user_id: int, login: str) -> None:
    """Imports and applied operations: activity + alert history (the case timeline gets its own IOCs/tasks)."""
    if e.context_type == "alert":
        alert = Alert.query.filter(Alert.alert_id == e.context_id).first()
        if alert is not None:
            _history_entry(alert, user_id, login, f"{message} (audit #{e.id})")
            db.session.commit()
    record_activity(user_id, f"{message} (audit #{e.id})",
                    case_id=e.context_id if e.context_type == "case" else None)
