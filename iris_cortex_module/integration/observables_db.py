"""Turn IRIS objects into Cortex observables, always inside a validated context.

An object is only usable in the context (case or alert) it belongs to: an IOC must be linked to
the case (ioc_link) or to the alert (alert IOCs), an evidence or datastore file must belong to
the case. This prevents reaching objects of other cases/customers by guessing ids.
"""
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from app.datamgmt.datastore.datastore_db import datastore_get_local_file_path
from app.models import CaseReceivedFile, DataStoreFile, Ioc, IocLink

from iris_cortex_module.core.client import FileInput
from iris_cortex_module.core.datatypes import (
    ObservableError, cortex_candidates, hash_kind, iris_tlp_to_cortex, normalize_value,
)
from iris_cortex_module.core.observables import (
    KIND_ALERT, KIND_CASE, KIND_EVIDENCE, KIND_FILE, KIND_IOC, RESPONDER_TYPE_ALERT, RESPONDER_TYPE_ARTIFACT,
    RESPONDER_TYPE_CASE, Observable, SourceObject, alert_entity, artifact_entity, case_entity, severity_to_thehive,
)
from iris_cortex_module.core.settings import CortexSettings
from iris_cortex_module.integration.access import Context
from iris_cortex_module.integration.errors import CortexModuleError

MAX_CONTEXT_ITEMS = 300
IRIS_DEFAULT_ZIP_PASSWORD = "infected"      # what IRIS uses for IOC files without an explicit password


def _not_found() -> CortexModuleError:
    return CortexModuleError("Objeto não encontrado neste caso/alerta.", 404)


def _tags(value) -> List[str]:
    return [t.strip() for t in str(value or "").split(",") if t.strip()][:50]


def _ioc_tlp(ioc) -> int:
    return iris_tlp_to_cortex(ioc.tlp.tlp_name if ioc.tlp else None)


def _ioc_in_context(ioc_id: int, ctx: Context):
    if ctx.context_type == "case":
        return (Ioc.query.join(IocLink, IocLink.ioc_id == Ioc.ioc_id)
                .filter(Ioc.ioc_id == ioc_id, IocLink.case_id == ctx.context_id).first())
    return next((i for i in (ctx.obj.iocs or []) if i.ioc_id == ioc_id), None)


def _context_iocs(ctx: Context) -> List[Any]:
    if ctx.context_type == "case":
        return (Ioc.query.join(IocLink, IocLink.ioc_id == Ioc.ioc_id)
                .filter(IocLink.case_id == ctx.context_id).order_by(Ioc.ioc_id).limit(MAX_CONTEXT_ITEMS).all())
    return list(ctx.obj.iocs or [])[:MAX_CONTEXT_ITEMS]


def _observables_for(candidates, tlp: int, pap: int, tags, settings: CortexSettings, errors: List[str]):
    result = []
    for data_type, value in candidates:
        try:
            normalized = normalize_value(data_type, value, settings.max_observable_length)
        except ObservableError as e:
            errors.append(f"{data_type}: {e}")
            continue
        result.append(Observable(data_type=data_type, data=normalized, label=normalized, tlp=tlp, pap=pap,
                                 tags=list(tags)))
    return result


def _ioc_artifact(ioc, case_id, pap: int) -> Dict[str, Any]:
    candidates = cortex_candidates(ioc.ioc_type.type_name if ioc.ioc_type else "", ioc.ioc_value or "")
    data_type, value = candidates[0] if candidates else ("other", ioc.ioc_value or "")
    return artifact_entity(ioc_id=ioc.ioc_id, value=value, data_type=data_type, tlp=_ioc_tlp(ioc), pap=pap,
                           tags=_tags(ioc.ioc_tags), message=ioc.ioc_description or "", case_id=case_id)


def resolve(kind: str, object_id: int, ctx: Context, settings: CortexSettings) -> SourceObject:
    pap = settings.default_pap
    errors: List[str] = []

    if kind == KIND_IOC:
        if not settings.enable_for_iocs:
            raise CortexModuleError("Cortex desativado para IOCs.", 403)
        ioc = _ioc_in_context(object_id, ctx)
        if ioc is None:
            raise _not_found()
        iris_type = ioc.ioc_type.type_name if ioc.ioc_type else ""
        tlp = _ioc_tlp(ioc)
        source = SourceObject(kind=kind, object_id=ioc.ioc_id, title=ioc.ioc_value or "", context_type=ctx.context_type,
                              context_id=ctx.context_id, customer_id=ctx.customer_id, customer_name=ctx.customer_name,
                              tlp=tlp, iris_type=iris_type)
        source.observables = _observables_for(
            cortex_candidates(iris_type, ioc.ioc_value or "", settings.datatype_mapping),
            tlp, pap, _tags(ioc.ioc_tags), settings, errors)
        source.responder_data_type = RESPONDER_TYPE_ARTIFACT
        source.responder_entity = _ioc_artifact(ioc, ctx.context_id if ctx.context_type == "case" else None, pap)

    elif kind == KIND_EVIDENCE:
        if not settings.enable_for_evidences:
            raise CortexModuleError("Cortex desativado para evidências.", 403)
        if ctx.context_type != "case":
            raise _not_found()
        ev = CaseReceivedFile.query.filter(CaseReceivedFile.id == object_id,
                                           CaseReceivedFile.case_id == ctx.context_id).first()
        if ev is None:
            raise _not_found()
        source = SourceObject(kind=kind, object_id=ev.id, title=ev.filename or f"evidence #{ev.id}",
                              context_type="case", context_id=ctx.context_id, customer_id=ctx.customer_id,
                              customer_name=ctx.customer_name, tlp=2, iris_type="evidence")
        candidates = []
        if ev.file_hash and hash_kind(ev.file_hash):
            candidates.append(("hash", ev.file_hash))
        if ev.filename:
            candidates.append(("filename", ev.filename))
        source.observables = _observables_for(candidates, 2, pap, [], settings, errors)
        if source.observables:
            first = source.observables[0]
            source.responder_data_type = RESPONDER_TYPE_ARTIFACT
            source.responder_entity = artifact_entity(ioc_id=ev.id, value=first.data, data_type=first.data_type,
                                                      tlp=2, pap=pap, tags=[], message=ev.file_description or "",
                                                      case_id=ctx.context_id)
            source.responder_entity["_id"] = source.responder_entity["id"] = f"iris-evidence-{ev.id}"

    elif kind == KIND_FILE:
        if not settings.enable_for_files:
            raise CortexModuleError("Cortex desativado para arquivos do datastore.", 403)
        if ctx.context_type != "case":
            raise _not_found()
        dsf = DataStoreFile.query.filter(DataStoreFile.file_id == object_id,
                                         DataStoreFile.file_case_id == ctx.context_id).first()
        if dsf is None:
            raise _not_found()
        source = SourceObject(kind=kind, object_id=dsf.file_id, title=dsf.file_original_name,
                              context_type="case", context_id=ctx.context_id, customer_id=ctx.customer_id,
                              customer_name=ctx.customer_name, tlp=2, iris_type="file")
        if (dsf.file_size or 0) > settings.max_file_size_mb * 1024 * 1024:
            errors.append(f"file: maior que {settings.max_file_size_mb} MB")
        else:
            source.observables = [Observable(data_type="file", data=None, label=dsf.file_original_name, tlp=2,
                                             pap=pap, filename=dsf.file_original_name)]
        if dsf.file_sha256 and hash_kind(dsf.file_sha256):
            source.observables += _observables_for([("hash", dsf.file_sha256)], 2, pap, [], settings, errors)

    elif kind == KIND_CASE:
        if not settings.enable_for_cases:
            raise CortexModuleError("Cortex desativado para casos.", 403)
        if ctx.context_type != "case" or object_id != ctx.context_id:
            raise _not_found()
        case = ctx.obj
        source = SourceObject(kind=kind, object_id=case.case_id, title=case.name or "", context_type="case",
                              context_id=case.case_id, customer_id=ctx.customer_id, customer_name=ctx.customer_name,
                              tlp=2, iris_type="case")
        source.responder_data_type = RESPONDER_TYPE_CASE
        source.responder_entity = case_entity(
            case_id=case.case_id, title=case.name, description=case.description,
            severity=severity_to_thehive(case.severity.severity_name if case.severity else None), tlp=2, pap=pap,
            tags=[t.tag_title for t in (case.tags or [])], owner=case.owner.name if case.owner else None,
            status="Resolved" if case.close_date else "Open", customer=ctx.customer_name,
            artifacts=[_ioc_artifact(i, case.case_id, pap) for i in _context_iocs(ctx)[:100]])

    elif kind == KIND_ALERT:
        if not settings.enable_for_alerts:
            raise CortexModuleError("Cortex desativado para alertas.", 403)
        if ctx.context_type != "alert" or object_id != ctx.context_id:
            raise _not_found()
        alert = ctx.obj
        source = SourceObject(kind=kind, object_id=alert.alert_id, title=alert.alert_title or "",
                              context_type="alert", context_id=alert.alert_id, customer_id=ctx.customer_id,
                              customer_name=ctx.customer_name, tlp=2, iris_type="alert")
        source.responder_data_type = RESPONDER_TYPE_ALERT
        source.responder_entity = alert_entity(
            alert_id=alert.alert_id, title=alert.alert_title, description=alert.alert_description,
            severity=severity_to_thehive(alert.severity.severity_name if alert.severity else None), tlp=2, pap=pap,
            tags=_tags(alert.alert_tags), source=alert.alert_source, source_ref=alert.alert_source_ref,
            customer=ctx.customer_name, artifacts=[_ioc_artifact(i, None, pap) for i in _context_iocs(ctx)[:100]])
    else:
        raise CortexModuleError("Tipo de objeto inválido.", 400)

    source.observable_errors = errors
    return source


def context_objects(ctx: Context, settings: CortexSettings) -> Dict[str, List[Dict[str, Any]]]:
    """Objects that can be picked when Cortex is opened from a case or an alert."""
    items: Dict[str, List[Dict[str, Any]]] = {"ioc": [], "evidence": [], "file": []}
    if settings.enable_for_iocs:
        items["ioc"] = [{"id": i.ioc_id, "label": i.ioc_value, "type": i.ioc_type.type_name if i.ioc_type else "",
                         "tlp": i.tlp.tlp_name if i.tlp else None} for i in _context_iocs(ctx)]
    if ctx.context_type == "case":
        if settings.enable_for_evidences:
            items["evidence"] = [{"id": e.id, "label": e.filename, "type": "evidence", "tlp": None}
                                 for e in CaseReceivedFile.query.filter(CaseReceivedFile.case_id == ctx.context_id)
                                 .order_by(CaseReceivedFile.id).limit(MAX_CONTEXT_ITEMS).all()]
        if settings.enable_for_files:
            items["file"] = [{"id": f.file_id, "label": f.file_original_name, "type": "file", "tlp": None,
                              "size": f.file_size}
                             for f in DataStoreFile.query.filter(DataStoreFile.file_case_id == ctx.context_id)
                             .order_by(DataStoreFile.file_id).limit(MAX_CONTEXT_ITEMS).all()]
    return items


def load_file(source: SourceObject, settings: CortexSettings) -> FileInput:
    """Datastore file content. IOC/protected files are stored by IRIS as password-protected zips:
    the single member is extracted in memory, with a decompression limit (zip bomb)."""
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    has_error, dsf = datastore_get_local_file_path(source.object_id, source.context_id)
    if has_error or dsf is None:
        raise _not_found()
    path = Path(dsf.file_local_name)
    if not path.is_file():
        raise CortexModuleError("O arquivo não existe mais no servidor.", 410)
    if dsf.file_is_ioc or dsf.file_password:
        password = (dsf.file_password or IRIS_DEFAULT_ZIP_PASSWORD).encode()
        try:
            with zipfile.ZipFile(path) as zf:
                members = [m for m in zf.infolist() if not m.is_dir()]
                if len(members) != 1:
                    raise CortexModuleError("Arquivo protegido com conteúdo inesperado.", 422)
                member = members[0]
                if member.file_size > max_bytes:
                    raise CortexModuleError(f"Arquivo maior que {settings.max_file_size_mb} MB.", 413)
                with zf.open(member, pwd=password) as fh:
                    content = fh.read(max_bytes + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as e:
            raise CortexModuleError(f"Não foi possível abrir o arquivo protegido: {e.__class__.__name__}", 422)
    else:
        if path.stat().st_size > max_bytes:
            raise CortexModuleError(f"Arquivo maior que {settings.max_file_size_mb} MB.", 413)
        content = path.read_bytes()
    if len(content) > max_bytes:
        raise CortexModuleError(f"Arquivo maior que {settings.max_file_size_mb} MB.", 413)
    return FileInput(filename=dsf.file_original_name or "sample", content=content)
