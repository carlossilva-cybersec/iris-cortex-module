"""Observables sent to Cortex and the TheHive-shaped entities expected by responders.

Responders from Cortex-Analyzers read ``data._type`` (case_artifact | case | alert), ``data._id``,
``data.data``, ``data.dataType``, ``data.tlp``, ``data.tags``, ``data.title``, ``data.caseId``...
The builders below map IRIS objects to that shape. Identifiers are prefixed (``iris-ioc-12``) so a
responder can never confuse them with TheHive ids.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

KIND_IOC = "ioc"
KIND_EVIDENCE = "evidence"
KIND_FILE = "file"
KIND_CASE = "case"
KIND_ALERT = "alert"
OBJECT_KINDS = (KIND_IOC, KIND_EVIDENCE, KIND_FILE, KIND_CASE, KIND_ALERT)

RESPONDER_TYPE_ARTIFACT = "thehive:case_artifact"
RESPONDER_TYPE_CASE = "thehive:case"
RESPONDER_TYPE_ALERT = "thehive:alert"


@dataclass
class Observable:
    """One value that can be analysed (``data_type`` is a Cortex data type)."""
    data_type: str
    data: Optional[str]                 # None for files
    label: str                          # shown to the analyst
    tlp: int = 2
    pap: int = 2
    tags: List[str] = field(default_factory=list)
    filename: Optional[str] = None      # files only

    def as_dict(self) -> Dict[str, Any]:
        return {"data_type": self.data_type, "data": self.data, "label": self.label, "tlp": self.tlp,
                "pap": self.pap, "tags": list(self.tags), "filename": self.filename}


@dataclass
class SourceObject:
    """The IRIS object the analyst selected, with the context it was opened in."""
    kind: str
    object_id: int
    title: str
    context_type: str                   # case | alert
    context_id: int
    customer_id: Optional[int]
    customer_name: Optional[str]
    tlp: int = 2
    iris_type: Optional[str] = None     # IOC type name
    observables: List[Observable] = field(default_factory=list)
    responder_data_type: Optional[str] = None
    responder_entity: Optional[Dict[str, Any]] = None
    observable_errors: List[str] = field(default_factory=list)   # values that could not be sent, with reason

    def summary(self) -> Dict[str, Any]:
        return {"kind": self.kind, "id": self.object_id, "title": self.title, "context_type": self.context_type,
                "context_id": self.context_id, "customer": self.customer_name, "tlp": self.tlp,
                "iris_type": self.iris_type, "observables": [o.as_dict() for o in self.observables],
                "responder_data_type": self.responder_data_type, "observable_errors": list(self.observable_errors)}


def artifact_entity(*, ioc_id: int, value: str, data_type: str, tlp: int, pap: int, tags: List[str],
                    message: str, case_id: Optional[int], created_at: Optional[str] = None) -> Dict[str, Any]:
    entity: Dict[str, Any] = {
        "_type": "case_artifact",
        "_id": f"iris-ioc-{ioc_id}",
        "id": f"iris-ioc-{ioc_id}",
        "dataType": data_type,
        "data": value,
        "tlp": tlp,
        "pap": pap,
        "tags": tags,
        "message": message or "",
        "ioc": True,
        "sighted": False,
        "status": "Ok",
    }
    if created_at:
        entity["createdAt"] = created_at
    if case_id is not None:
        entity["case"] = {"_type": "case", "_id": f"iris-case-{case_id}", "id": f"iris-case-{case_id}",
                          "caseId": case_id}
    return entity


def case_entity(*, case_id: int, title: str, description: str, severity: int, tlp: int, pap: int,
                tags: List[str], owner: Optional[str], status: str, customer: Optional[str],
                artifacts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "_type": "case",
        "_id": f"iris-case-{case_id}",
        "id": f"iris-case-{case_id}",
        "caseId": case_id,
        "title": title or "",
        "description": description or "",
        "severity": severity,
        "tlp": tlp,
        "pap": pap,
        "tags": tags,
        "owner": owner or "",
        "status": status,
        "customFields": {"iris-customer": {"string": customer or ""}},
        "artifacts": artifacts or [],
    }


def alert_entity(*, alert_id: int, title: str, description: str, severity: int, tlp: int, pap: int,
                 tags: List[str], source: str, source_ref: str, customer: Optional[str],
                 artifacts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "_type": "alert",
        "_id": f"iris-alert-{alert_id}",
        "id": f"iris-alert-{alert_id}",
        "title": title or "",
        "description": description or "",
        "severity": severity,
        "tlp": tlp,
        "pap": pap,
        "tags": tags,
        "type": "iris",
        "source": source or "",
        "sourceRef": source_ref or f"iris-alert-{alert_id}",
        "customFields": {"iris-customer": {"string": customer or ""}},
        "artifacts": artifacts or [],
    }


def severity_to_thehive(severity_name: Optional[str]) -> int:
    """IRIS severity names -> TheHive 1..4 (low, medium, high, critical)."""
    name = (severity_name or "").strip().lower()
    return {"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(name, 2)
