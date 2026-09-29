"""Use cases: catalog, analyzer/responder execution, job follow-up, results, import, operations.

Callable from HTTP routes (web process, current_user available) and from Celery tasks
(``poll_once`` only, no current_user).
"""
import datetime
import threading
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple

from flask import current_app, request
from flask_login import current_user
from sqlalchemy.orm.attributes import flag_modified

from app import db
from app.models import CaseTasks, Ioc, IocType, TaskStatus, Tlp
from app.models.cases import Cases
from app.models.models import Tags

from iris_cortex_module.core import client as cortex
from iris_cortex_module.core.client import CortexClient, CortexError
from iris_cortex_module.core.datatypes import CORTEX_TLP_NAMES
from iris_cortex_module.core.observables import KIND_ALERT, KIND_CASE, OBJECT_KINDS, SourceObject
from iris_cortex_module.core.policy import (
    ROLE_ADMIN, ROLE_ANALYZER, ROLE_RESPONDER, ROLE_VIEW, PolicyError, check_classification, responder_role,
)
from iris_cortex_module.core.results import parse_report
from iris_cortex_module.core.settings import ConfigError, CortexSettings
from iris_cortex_module.integration import audit, observables_db
from iris_cortex_module.integration.access import (
    Context, require_role, resolve_context, roles_for_current_user,
)
from iris_cortex_module.integration.config_store import load_settings
from iris_cortex_module.integration.errors import CortexModuleError
from iris_cortex_module.integration.models import (
    CORTEX_TO_LOCAL, STATUS_ERROR, STATUS_FAILURE, STATUS_PENDING, STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_WAITING,
    CortexExecution,
)

WORKER_CACHE_TTL = 60
_worker_cache: Dict[Tuple[str, str, str, str], Tuple[float, List[Dict[str, Any]]]] = {}
_cache_lock = threading.Lock()

_ERROR_HTTP = {
    cortex.CortexAuthError: 502, cortex.CortexPermissionError: 502, cortex.CortexNotFound: 404,
    cortex.CortexRateLimited: 429, cortex.CortexRequestError: 400, cortex.CortexTLSError: 502,
    cortex.CortexTimeout: 504, cortex.CortexUnavailable: 503, cortex.CortexBadResponse: 502,
}
LOCAL_TLP_NAMES = {0: "clear", 1: "green", 2: "amber", 3: "red"}


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


# ---------------------------------------------------------------------------------- helpers

def _module_error(err: CortexError) -> CortexModuleError:
    current_app.logger.warning(f"iris_cortex_module: Cortex error {err.__class__.__name__}: {err.detail}")
    return CortexModuleError(err.user_message, _ERROR_HTTP.get(type(err), 502))


def _client(settings: CortexSettings, customer_name: Optional[str]) -> CortexClient:
    try:
        return CortexClient.from_settings(settings, customer_name)
    except ConfigError as e:
        raise CortexModuleError(f"Módulo Cortex mal configurado: {e}", 503)
    except cortex.CortexAuthError:
        raise CortexModuleError(f"API key do Cortex não configurada: defina a variável "
                                f"{settings.api_key_env_for(customer_name)} e reinicie app e worker.", 503)


def _workers(settings: CortexSettings, client: CortexClient, kind: str, data_type: str,
             customer_name: Optional[str]) -> List[Dict[str, Any]]:
    key = (kind, data_type, settings.api_key_env_for(customer_name), settings.cortex_url)
    with _cache_lock:
        hit = _worker_cache.get(key)
        if hit and time.monotonic() - hit[0] < WORKER_CACHE_TTL:
            return hit[1]
    try:
        workers = client.analyzers_for_type(data_type) if kind == "analyzer" else client.responders_for_type(data_type)
    except CortexError as e:
        raise _module_error(e)
    offered = settings.analyzer_offered if kind == "analyzer" else settings.responder_offered
    workers = sorted((w for w in workers if offered(w.get("name", ""))), key=lambda w: w.get("name", "").lower())
    with _cache_lock:
        _worker_cache[key] = (time.monotonic(), workers)
    return workers


def _classification_error(settings: CortexSettings, tlp: int, pap: int) -> Optional[str]:
    try:
        check_classification(settings, tlp, pap)
    except PolicyError as e:
        return e.message
    return None


def _count_recent(worker_type: str, user_id: int) -> int:
    since = _now() - datetime.timedelta(hours=1)
    return CortexExecution.query.filter(CortexExecution.user_id == user_id, CortexExecution.worker_type == worker_type,
                                        CortexExecution.created_at >= since).count()


def _parse_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise CortexModuleError(f"Campo {field} inválido.", 400)


def _load_target(body: Mapping[str, Any], settings: CortexSettings, write: bool) -> Tuple[Context, SourceObject]:
    kind = str(body.get("kind") or "")
    if kind not in OBJECT_KINDS:
        raise CortexModuleError("Tipo de objeto inválido.", 400)
    ctx = resolve_context(str(body.get("context_type") or ""), _parse_int(body.get("context_id"), "context_id"), write)
    return ctx, observables_db.resolve(kind, _parse_int(body.get("object_id"), "object_id"), ctx, settings)


def _new_execution(settings: CortexSettings, ctx: Context, source: SourceObject, worker: Dict[str, Any],
                   worker_type: str, data_type: str, observable: str, tlp: int, pap: int,
                   payload: Dict[str, Any], request_uuid=None, privileged: bool = False) -> CortexExecution:
    e = CortexExecution(
        uuid=uuid.uuid4(), request_uuid=request_uuid, created_at=_now(), updated_at=_now(), poll_count=0,
        user_id=current_user.id, user_login=current_user.user, client_ip=request.remote_addr,
        is_from_api=request.cookies.get("session") is None,
        context_type=ctx.context_type, context_id=ctx.context_id, customer_id=ctx.customer_id,
        customer_name=ctx.customer_name, object_kind=source.kind, object_id=source.object_id,
        object_label=source.title[:500], worker_type=worker_type, worker_id=worker["id"],
        worker_name=worker.get("name"), worker_version=worker.get("version"), privileged=privileged,
        data_type=data_type, observable=(observable or "")[:8192], tlp=tlp, pap=pap,
        parameters={}, request_payload=payload, cortex_url=settings.cortex_url, status=STATUS_PENDING,
    )
    db.session.add(e)
    db.session.commit()
    return e


def _submitted(e: CortexExecution, job: Dict[str, Any], settings: CortexSettings) -> None:
    e.cortex_job_id = job["id"]
    e.cortex_status = job.get("status")
    e.status = CORTEX_TO_LOCAL.get(job.get("status"), STATUS_WAITING)
    e.updated_at = _now()
    e.next_poll_at = _now() + datetime.timedelta(seconds=settings.poll_interval)
    db.session.commit()
    if e.status in (STATUS_SUCCESS, STATUS_FAILURE):
        # Cached job returned already finished: fetch the report right away.
        poll_once(e.id, settings)
    else:
        from iris_cortex_module.integration import jobs
        jobs.schedule_poll(e.id, settings.poll_interval)


def _submit_failed(e: CortexExecution, err: CortexError, settings: CortexSettings) -> None:
    e.status = STATUS_ERROR
    e.error_message = err.user_message
    e.error_detail = err.detail
    e.finished_at = e.updated_at = _now()
    db.session.commit()
    audit.record_completion(e, settings.add_timeline_event, settings.write_ioc_tab)


# ---------------------------------------------------------------------------------- read side

def status() -> Dict[str, Any]:
    settings = load_settings()
    roles = require_role(settings, ROLE_VIEW)
    result: Dict[str, Any] = {"cortex_url": settings.cortex_url, "roles": sorted(roles),
                              "max_tlp": CORTEX_TLP_NAMES.get(settings.max_tlp), "poll_interval": settings.poll_interval}
    try:
        client = _client(settings, None)
        info = client.status()
        user = client.current_user()
        result.update({"reachable": True, "version": info.get("version"), "organization": user.get("organization"),
                       "cortex_user": user.get("name"), "cortex_roles": user.get("roles")})
        if {"orgadmin", "superadmin"}.intersection(r.lower() for r in user.get("roles") or []):
            result["warning"] = ("A API key usada pertence a um administrador do Cortex. Use um usuário apenas com "
                                 "o papel 'analyze': chaves de administrador expõem a configuração dos analyzers.")
    except CortexModuleError as e:
        result.update({"reachable": False, "error": e.message})
    except CortexError as e:
        result.update({"reachable": False, "error": e.user_message})
    return result


def _worker_view(w: Dict[str, Any], allowed: bool, reason: str, **extra) -> Dict[str, Any]:
    view = {k: w.get(k) for k in ("id", "name", "version", "description", "author", "url", "license",
                                   "dataTypeList", "rate", "rateUnit", "jobCache")}
    view.update({"allowed": allowed, "reason": reason})
    view.update(extra)
    return view


def _can_write(ctx: Context) -> bool:
    try:
        resolve_context(ctx.context_type, ctx.context_id, write=True)
        return True
    except CortexModuleError:
        return False


def catalog(kind: str, object_id: int, context_type: str, context_id: int) -> Dict[str, Any]:
    settings = load_settings()
    roles = require_role(settings, ROLE_VIEW)
    ctx, source = _load_target({"kind": kind, "object_id": object_id, "context_type": context_type,
                                "context_id": context_id}, settings, write=False)
    can_write = _can_write(ctx)
    result: Dict[str, Any] = {"object": source.summary(), "roles": sorted(roles), "can_write": can_write,
                              "analyzers": [], "responders": [], "cortex_error": None,
                              "max_tlp": CORTEX_TLP_NAMES.get(settings.max_tlp)}
    if kind in (KIND_CASE, KIND_ALERT):
        result["context_objects"] = observables_db.context_objects(ctx, settings)

    try:
        client = _client(settings, ctx.customer_name)
        for index, obs in enumerate(source.observables):
            blocked = _classification_error(settings, obs.tlp, obs.pap)
            for w in _workers(settings, client, "analyzer", obs.data_type, ctx.customer_name):
                reason = blocked or ("" if ROLE_ANALYZER in roles else "Sem permissão para executar analyzers") \
                    or ("" if can_write else "Acesso somente leitura a este caso/alerta")
                result["analyzers"].append(_worker_view(w, not reason, reason, observable_index=index,
                                                        data_type=obs.data_type))
        if source.responder_data_type:
            blocked = _classification_error(settings, source.tlp, settings.default_pap)
            for w in _workers(settings, client, "responder", source.responder_data_type, ctx.customer_name):
                needed = responder_role(settings, w.get("name", ""))
                privileged = needed != ROLE_RESPONDER
                reason = blocked or ("" if needed in roles else
                                     ("Responder privilegiado: exige permissão específica" if privileged
                                      else "Sem permissão para executar responders")) \
                    or ("" if can_write else "Acesso somente leitura a este caso/alerta")
                result["responders"].append(_worker_view(w, not reason, reason, privileged=privileged,
                                                         data_type=source.responder_data_type))
    except CortexModuleError as e:
        result["cortex_error"] = e.message

    result["history"] = [x.to_dict() for x in CortexExecution.query.filter(
        CortexExecution.context_type == ctx.context_type, CortexExecution.context_id == ctx.context_id,
        CortexExecution.object_kind == source.kind, CortexExecution.object_id == source.object_id)
        .order_by(CortexExecution.created_at.desc()).limit(50).all()]
    return result


def _execution_for(execution_id: int, write: bool) -> Tuple[CortexExecution, Context]:
    e = CortexExecution.query.filter(CortexExecution.id == execution_id).first()
    if e is None:
        raise CortexModuleError("Execução não encontrada.", 404)
    ctx = resolve_context(e.context_type, e.context_id, write=write)
    return e, ctx


def get_execution(execution_id: int, include_report: bool = False) -> Dict[str, Any]:
    settings = load_settings()
    require_role(settings, ROLE_VIEW)
    e, _ = _execution_for(execution_id, write=False)
    if not e.is_final and e.cortex_job_id:
        grace = datetime.timedelta(seconds=2 * settings.poll_interval)
        if e.next_poll_at is None or _now() > e.next_poll_at + grace:
            # The worker task was lost (restart, broker outage): follow the job from here.
            poll_once(e.id, settings)
            db.session.refresh(e)
    return e.to_dict(include_report=include_report)


def history(context_type: str, context_id: int) -> List[Dict[str, Any]]:
    settings = load_settings()
    require_role(settings, ROLE_VIEW)
    ctx = resolve_context(context_type, context_id, write=False)
    return [x.to_dict() for x in CortexExecution.query.filter(
        CortexExecution.context_type == ctx.context_type, CortexExecution.context_id == ctx.context_id)
        .order_by(CortexExecution.created_at.desc()).limit(200).all()]


def logs(page: int, per_page: int, filters: Mapping[str, Any]) -> Dict[str, Any]:
    settings = load_settings()
    require_role(settings, ROLE_ADMIN)
    q = CortexExecution.query
    for field in ("status", "worker_type", "context_type", "object_kind", "user_login"):
        if filters.get(field):
            q = q.filter(getattr(CortexExecution, field) == filters[field])
    if filters.get("context_id"):
        q = q.filter(CortexExecution.context_id == filters["context_id"])
    if filters.get("worker"):
        q = q.filter(CortexExecution.worker_name.ilike(f"%{filters['worker']}%"))
    total = q.count()
    rows = q.order_by(CortexExecution.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for r in rows:
        d = r.to_dict()
        d.update({"client_ip": r.client_ip, "is_from_api": r.is_from_api, "request_payload": r.request_payload,
                  "error_detail": r.error_detail, "customer_name": r.customer_name})
        items.append(d)
    return {"total": total, "page": page, "per_page": per_page, "items": items}


# ---------------------------------------------------------------------------------- execution

def run_analyzers(body: Mapping[str, Any]) -> List[Dict[str, Any]]:
    settings = load_settings()
    require_role(settings, ROLE_ANALYZER)
    ctx, source = _load_target(body, settings, write=True)
    if not source.observables:
        raise CortexModuleError("Este objeto não tem observáveis compatíveis com o Cortex.", 400)
    index = _parse_int(body.get("observable_index", 0), "observable_index")
    if not 0 <= index < len(source.observables):
        raise CortexModuleError("Observável inválido.", 400)
    obs = source.observables[index]

    ids = body.get("analyzer_ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
        raise CortexModuleError("Selecione ao menos um analyzer.", 400)
    ids = list(dict.fromkeys(ids))
    if len(ids) > settings.max_analyzers_per_request:
        raise CortexModuleError(f"Máximo de {settings.max_analyzers_per_request} analyzers por execução.", 400)

    blocked = _classification_error(settings, obs.tlp, obs.pap)
    if blocked:
        audit.record_activity(current_user.id, f"cortex analyzer refused by TLP policy on \"{obs.label}\"",
                              case_id=ctx.context_id if ctx.context_type == "case" else None, display=False)
        raise CortexModuleError(blocked, 403)
    if settings.rate_limit_analyzer_user_hour and \
            _count_recent("analyzer", current_user.id) + len(ids) > settings.rate_limit_analyzer_user_hour:
        raise CortexModuleError("Limite de execuções de analyzers por hora atingido.", 429)

    client = _client(settings, ctx.customer_name)
    compatible = {w["id"]: w for w in _workers(settings, client, "analyzer", obs.data_type, ctx.customer_name)}
    missing = [i for i in ids if i not in compatible]
    if missing:
        raise CortexModuleError(f"Analyzer indisponível ou incompatível com o tipo {obs.data_type}: "
                                f"{', '.join(missing)}", 400)

    file_input = observables_db.load_file(source, settings) if obs.data_type == "file" else None
    message = f"IRIS {source.kind} #{source.object_id} ({ctx.context_type} #{ctx.context_id}) by {current_user.user}"
    label = f"iris-{ctx.context_type}-{ctx.context_id}"
    results = []
    for analyzer_id in ids:
        worker = compatible[analyzer_id]
        payload = {"dataType": obs.data_type, "tlp": obs.tlp, "pap": obs.pap, "message": message, "label": label,
                   "force": settings.force_run}
        if file_input:
            payload.update({"filename": file_input.filename, "size": len(file_input.content)})
        else:
            payload["data"] = obs.data
        e = _new_execution(settings, ctx, source, worker, "analyzer", obs.data_type,
                           obs.data if obs.data is not None else obs.filename, obs.tlp, obs.pap, payload)
        try:
            job = client.run_analyzer(analyzer_id, data_type=obs.data_type, data=obs.data, file=file_input,
                                      tlp=obs.tlp, pap=obs.pap, message=message, label=label, force=settings.force_run)
            _submitted(e, job, settings)
        except CortexError as err:
            current_app.logger.warning(f"iris_cortex_module: analyzer {analyzer_id} submit failed: {err.detail}")
            _submit_failed(e, err, settings)
        db.session.refresh(e)
        results.append(e.to_dict())
    audit.record_activity(current_user.id, f"started {len(ids)} cortex analyzer(s) on \"{obs.label}\"",
                          case_id=ctx.context_id if ctx.context_type == "case" else None)
    return results


def run_responder(body: Mapping[str, Any]) -> Dict[str, Any]:
    settings = load_settings()
    require_role(settings, ROLE_VIEW)
    ctx, source = _load_target(body, settings, write=True)
    if not source.responder_data_type or not source.responder_entity:
        raise CortexModuleError("Este objeto não aceita responders.", 400)
    if body.get("confirm") is not True:
        raise CortexModuleError("A execução de responders exige confirmação explícita (confirm=true).", 400)
    try:
        request_uuid = uuid.UUID(str(body.get("request_uuid")))
    except (TypeError, ValueError):
        raise CortexModuleError("request_uuid inválido.", 400)
    if CortexExecution.query.filter(CortexExecution.request_uuid == request_uuid).first():
        raise CortexModuleError("Esta solicitação já foi enviada.", 409)

    responder_id = str(body.get("responder_id") or "")
    client = _client(settings, ctx.customer_name)
    workers = {w["id"]: w for w in _workers(settings, client, "responder", source.responder_data_type,
                                            ctx.customer_name)}
    worker = workers.get(responder_id)
    if worker is None:
        raise CortexModuleError("Responder indisponível ou incompatível com este objeto.", 400)
    needed = responder_role(settings, worker.get("name", ""))
    try:
        require_role(settings, needed)
    except CortexModuleError:
        audit.record_activity(current_user.id, f"cortex responder {worker.get('name')} refused: missing {needed}",
                              case_id=ctx.context_id if ctx.context_type == "case" else None, display=False)
        raise
    blocked = _classification_error(settings, source.tlp, settings.default_pap)
    if blocked:
        raise CortexModuleError(blocked, 403)
    if settings.rate_limit_responder_user_hour and \
            _count_recent("responder", current_user.id) >= settings.rate_limit_responder_user_hour:
        raise CortexModuleError("Limite de execuções de responders por hora atingido.", 429)

    message = f"IRIS {source.kind} #{source.object_id} ({ctx.context_type} #{ctx.context_id}) by {current_user.user}"
    label = f"iris-{ctx.context_type}-{ctx.context_id}"
    entity = source.responder_entity
    payload = {"dataType": source.responder_data_type, "tlp": source.tlp, "pap": settings.default_pap,
               "message": message, "label": label, "data": entity}
    observable = entity.get("data") or entity.get("title") or source.title
    e = _new_execution(settings, ctx, source, worker, "responder", source.responder_data_type, str(observable),
                       source.tlp, settings.default_pap, payload, request_uuid=request_uuid,
                       privileged=needed != ROLE_RESPONDER)
    try:
        job = client.run_responder(responder_id, data_type=source.responder_data_type, data=entity, tlp=source.tlp,
                                   pap=settings.default_pap, message=message, label=label)
        _submitted(e, job, settings)
    except CortexError as err:
        current_app.logger.warning(f"iris_cortex_module: responder {responder_id} submit failed: {err.detail}")
        _submit_failed(e, err, settings)
    audit.record_activity(current_user.id, f"started cortex responder {worker.get('name')} on \"{observable}\"",
                          case_id=ctx.context_id if ctx.context_type == "case" else None)
    db.session.refresh(e)
    return e.to_dict()


# ---------------------------------------------------------------------------------- job follow-up

def poll_once(execution_id: int, settings: Optional[CortexSettings] = None) -> bool:
    """Advance one execution. Returns True when it is final. Safe to call concurrently."""
    e = CortexExecution.query.filter(CortexExecution.id == execution_id).with_for_update().first()
    if e is None or e.is_final:
        db.session.commit()
        return True
    if settings is None:
        try:
            settings = load_settings()
        except CortexModuleError as err:
            return _finish(e, STATUS_ERROR, None, err.message, "module unavailable while the job was running")

    if _now() > e.created_at + datetime.timedelta(seconds=settings.job_timeout):
        return _finish(e, STATUS_TIMEOUT, settings,
                       f"O job não terminou em {settings.job_timeout} s (timeout configurado).", "")
    try:
        client = _client(settings, e.customer_name)
        job = client.get_job(e.cortex_job_id)
        cortex_status = job.get("status")
        e.cortex_status = cortex_status
        if cortex_status in (cortex.JOB_SUCCESS, cortex.JOB_FAILURE):
            _, report = client.job_report(e.cortex_job_id)
            parsed = parse_report(report, settings.max_report_kb * 1024)
            e.taxonomies = parsed.taxonomies
            e.verdict = parsed.verdict
            e.highlights = [list(h) for h in parsed.highlights]
            e.report = parsed.full
            e.report_truncated = parsed.full_truncated
            e.artifacts = [a.as_dict() for a in parsed.artifacts]
            e.operations = parsed.operations
            if cortex_status == cortex.JOB_SUCCESS and parsed.success:
                return _finish(e, STATUS_SUCCESS, settings, None, "")
            return _finish(e, STATUS_FAILURE, settings,
                           parsed.error_message or job.get("errorMessage") or "O job falhou no Cortex.", "")
        if cortex_status == cortex.JOB_DELETED:
            return _finish(e, STATUS_ERROR, settings, "O job foi excluído no Cortex.", "")
        e.status = CORTEX_TO_LOCAL.get(cortex_status, e.status)
    except CortexModuleError as err:
        # Client configuration problem (e.g. API key variable removed): keep following the job
        # until job_timeout, so fixing the configuration recovers the result.
        e.error_detail = f"last poll error: {err.message}"
    except CortexError as err:
        if not err.retryable:
            return _finish(e, STATUS_ERROR, settings, err.user_message, err.detail)
        e.error_detail = f"last poll error: {err.detail}"
    e.poll_count = (e.poll_count or 0) + 1
    e.updated_at = _now()
    e.next_poll_at = _now() + datetime.timedelta(seconds=settings.poll_interval)
    db.session.commit()
    return False


def _finish(e: CortexExecution, status: str, settings: Optional[CortexSettings], message: Optional[str],
            detail: str) -> bool:
    e.status = status
    e.error_message = message
    if detail:
        e.error_detail = detail
    e.finished_at = e.updated_at = _now()
    e.next_poll_at = None
    db.session.commit()        # releases the row lock: only this caller records the completion
    audit.record_completion(e, settings.add_timeline_event if settings else True,
                            settings.write_ioc_tab if settings else False)
    return True


def reconcile_stale(limit: int = 100) -> List[int]:
    """Executions whose polling task was lost. Returns their ids."""
    cutoff = _now() - datetime.timedelta(minutes=2)
    rows = CortexExecution.query.with_entities(CortexExecution.id).filter(
        CortexExecution.status.notin_([STATUS_SUCCESS, STATUS_FAILURE, STATUS_TIMEOUT, STATUS_ERROR]),
        CortexExecution.cortex_job_id.isnot(None),
        CortexExecution.next_poll_at < cutoff).limit(limit).all()
    return [r.id for r in rows]


# ---------------------------------------------------------------------------------- results → IRIS

def _iris_tlp_id(level: int) -> Optional[int]:
    row = Tlp.query.filter(Tlp.tlp_name == LOCAL_TLP_NAMES.get(level, "amber")).first()
    return row.tlp_id if row else None


def import_artifacts(execution_id: int, indexes: Any) -> Dict[str, Any]:
    settings = load_settings()
    require_role(settings, ROLE_ANALYZER)
    e, ctx = _execution_for(execution_id, write=True)
    if e.status != STATUS_SUCCESS:
        raise CortexModuleError("Só é possível importar resultados de execuções concluídas com sucesso.", 400)
    if not isinstance(indexes, list) or not indexes or not all(isinstance(i, int) for i in indexes):
        raise CortexModuleError("Selecione os itens a importar.", 400)
    indexes = list(dict.fromkeys(indexes))
    if len(indexes) > settings.max_artifacts_import:
        raise CortexModuleError(f"Máximo de {settings.max_artifacts_import} itens por importação.", 400)
    already = {i.get("index") for i in (e.imported or [])}
    by_index = {a["index"]: a for a in (e.artifacts or [])}

    results = []
    for idx in indexes:
        art = by_index.get(idx)
        if art is None or not art.get("importable"):
            results.append({"index": idx, "ok": False, "message": "Item não importável"})
            continue
        if idx in already:
            results.append({"index": idx, "ok": False, "message": "Já importado"})
            continue
        ioc_type = IocType.query.filter(IocType.type_name == art["iris_type"]).first()
        # Never lower the classification of what came back: keep the stricter of the two TLPs.
        tlp_id = _iris_tlp_id(max(e.tlp or 2, art.get("tlp") if isinstance(art.get("tlp"), int) else 0))
        if ioc_type is None or tlp_id is None:
            results.append({"index": idx, "ok": False, "message": f"Tipo {art['iris_type']} inexistente no IRIS"})
            continue
        description = (f"Imported from Cortex {e.worker_name} (execution #{e.id}, job {e.cortex_job_id}) "
                       f"on {e.observable}. {art.get('message') or ''}").strip()
        tags = ",".join(dict.fromkeys(["cortex", e.worker_name or ""] + list(art.get("tags") or [])))[:500]
        try:
            ioc_id, message = _create_ioc(ctx, art["data"], ioc_type.type_id, tlp_id, description, tags)
        except Exception as err:        # business validation errors from IRIS
            db.session.rollback()
            results.append({"index": idx, "ok": False, "message": getattr(err, "message", str(err))[:300]})
            continue
        results.append({"index": idx, "ok": True, "ioc_id": ioc_id, "value": art["data"], "message": message})

    imported = [r for r in results if r["ok"]]
    if imported:
        e.imported = (e.imported or []) + [{"index": r["index"], "ioc_id": r["ioc_id"], "value": r["value"],
                                            "by": current_user.user, "at": _now().isoformat()} for r in imported]
        flag_modified(e, "imported")
        db.session.commit()
        audit.record_object_change(e, f"imported {len(imported)} IOC(s) from cortex {e.worker_name}",
                                   current_user.id, current_user.user)
    return {"results": results, "execution": e.to_dict()}


def _create_ioc(ctx: Context, value: str, type_id: int, tlp_id: int, description: str, tags: str) -> Tuple[int, str]:
    if ctx.context_type == "case":
        from app.business.iocs import create as iris_create_ioc
        ioc, message = iris_create_ioc({"ioc_value": value, "ioc_type_id": type_id, "ioc_tlp_id": tlp_id,
                                        "ioc_description": description, "ioc_tags": tags,
                                        "custom_attributes": {}}, ctx.context_id)
        return ioc.ioc_id, message
    # Alerts: IRIS' add_ioc() updates a case state, so the IOC is found or created directly.
    ioc = Ioc.query.filter(Ioc.ioc_value == value, Ioc.ioc_type_id == type_id).first()
    if ioc is None:
        ioc = Ioc(ioc_value=value, ioc_type_id=type_id, ioc_tlp_id=tlp_id, ioc_description=description,
                  ioc_tags=tags, user_id=current_user.id, custom_attributes={})
        db.session.add(ioc)
        db.session.commit()
    alert = ctx.obj
    if not any(i.ioc_id == ioc.ioc_id for i in alert.iocs):
        alert.iocs.append(ioc)
        db.session.commit()
        return ioc.ioc_id, "IOC adicionado ao alerta"
    return ioc.ioc_id, "IOC já estava no alerta"


def apply_operation(execution_id: int, index: int) -> Dict[str, Any]:
    settings = load_settings()
    e, ctx = _execution_for(execution_id, write=True)
    if e.worker_type != "responder" or e.status != STATUS_SUCCESS:
        raise CortexModuleError("Operações só podem ser aplicadas a partir de responders concluídos.", 400)
    require_role(settings, responder_role(settings, e.worker_name or ""))
    ops = list(e.operations or [])
    op = next((o for o in ops if o.get("index") == index), None)
    if op is None or not op.get("supported"):
        raise CortexModuleError("Operação não suportada pelo IRIS.", 400)
    if op.get("applied"):
        raise CortexModuleError("Operação já aplicada.", 409)
    params = op.get("params") or {}
    op_type = op["type"]

    if op_type == "AddTagToArtifact":
        if e.object_kind != "ioc":
            raise CortexModuleError("Tags de artefato só se aplicam a IOCs.", 400)
        target = Ioc.query.filter(Ioc.ioc_id == e.object_id).first()
        tags = [t for t in (target.ioc_tags or "").split(",") if t]
        if params["tag"] not in tags:
            target.ioc_tags = ",".join(tags + [params["tag"]])[:512]
        done = f"tag \"{params['tag']}\" added to IOC {target.ioc_value}"
    elif op_type == "AddTagToCase":
        if ctx.context_type != "case":
            raise CortexModuleError("Esta operação só se aplica a casos.", 400)
        tag = Tags(tag_title=str(params["tag"])[:200]).save()
        case = Cases.query.filter(Cases.case_id == ctx.context_id).first()
        if all(t.id != tag.id for t in case.tags):
            case.tags.append(tag)
        done = f"tag \"{params['tag']}\" added to case"
    elif op_type == "AddTagToAlert":
        if ctx.context_type != "alert":
            raise CortexModuleError("Esta operação só se aplica a alertas.", 400)
        tags = [t for t in (ctx.obj.alert_tags or "").split(",") if t]
        if params["tag"] not in tags:
            ctx.obj.alert_tags = ",".join(tags + [str(params["tag"])[:200]])
        done = f"tag \"{params['tag']}\" added to alert"
    elif op_type == "CreateTask":
        if ctx.context_type != "case":
            raise CortexModuleError("Tarefas só podem ser criadas em casos.", 400)
        status = TaskStatus.query.filter(TaskStatus.status_name == "To do").first()
        task = CaseTasks(task_title=str(params["title"])[:250], task_description=str(params.get("description") or ""),
                         task_tags="cortex", task_open_date=_now(), task_last_update=_now(),
                         task_userid_open=current_user.id, task_userid_update=current_user.id,
                         task_status_id=status.id if status else None, task_case_id=ctx.context_id,
                         custom_attributes={})
        db.session.add(task)
        done = f"task \"{params['title']}\" created"
    else:
        raise CortexModuleError("Operação não suportada pelo IRIS.", 400)

    op.update({"applied": True, "applied_by": current_user.user, "applied_at": _now().isoformat()})
    e.operations = ops
    flag_modified(e, "operations")
    db.session.commit()
    audit.record_object_change(e, f"applied cortex {e.worker_name} operation {op_type}: {done}",
                               current_user.id, current_user.user)
    return e.to_dict()
