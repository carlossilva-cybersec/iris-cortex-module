"""Cortex report parsing and presentation.

Everything returned by an analyzer is untrusted input (it is built from third-party services
and, often, from attacker-controlled content). The parser:

* bounds depth, number of keys/items and string length, strips control characters;
* keeps the full report as JSON data only -- the UI renders it as text nodes, never as HTML;
* normalises taxonomies to the four Cortex levels;
* validates artifacts before they can be imported as IOCs;
* flags responder operations IRIS can apply.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from iris_cortex_module.core.datatypes import (
    CORTEX_TLP_NAMES, ObservableError, iris_type_for_artifact, normalize_value,
)

LEVELS = ("info", "safe", "suspicious", "malicious")
LEVEL_RANK = {level: i for i, level in enumerate(LEVELS)}
SUPPORTED_OPERATIONS = ("AddTagToArtifact", "AddTagToCase", "AddTagToAlert", "CreateTask")

MAX_DEPTH = 20
MAX_KEYS = 500
MAX_ITEMS = 1000
MAX_STRING = 10_000
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: Any, max_length: int = MAX_STRING) -> str:
    text = "" if value is None else str(value)
    text = _CONTROL_RE.sub("", text)
    return text if len(text) <= max_length else text[:max_length] + "…"


def sanitize_json(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return "[depth limit]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_KEYS:
                out["[truncated]"] = f"{len(value) - MAX_KEYS} more keys"
                break
            out[clean_text(k, 200)] = sanitize_json(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [sanitize_json(v, depth + 1) for v in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"[{len(value) - MAX_ITEMS} more items]")
        return items
    return clean_text(value)


def bounded_json(value: Any, max_bytes: int) -> Tuple[Any, bool]:
    """Return (value, truncated). Oversized values are replaced by a textual preview."""
    serialized = json.dumps(value, ensure_ascii=False, default=str)
    if len(serialized.encode("utf-8")) <= max_bytes:
        return value, False
    preview = serialized.encode("utf-8")[:max_bytes].decode("utf-8", "ignore")
    return {"_truncated": True, "_original_size": len(serialized), "_preview": preview}, True


def normalize_taxonomy(tax: Any) -> Optional[Dict[str, str]]:
    if not isinstance(tax, dict):
        return None
    level = clean_text(tax.get("level"), 20).lower()
    return {
        "level": level if level in LEVEL_RANK else "info",
        "namespace": clean_text(tax.get("namespace"), 100),
        "predicate": clean_text(tax.get("predicate"), 100),
        "value": clean_text(tax.get("value"), 200),
    }


def verdict(taxonomies: List[Dict[str, str]]) -> Optional[str]:
    if not taxonomies:
        return None
    return max((t["level"] for t in taxonomies), key=lambda lv: LEVEL_RANK[lv])


def flatten_scalars(value: Any, prefix: str = "", limit: int = 40) -> List[Tuple[str, str]]:
    """Top scalar fields of the full report, for a readable 'key: value' summary."""
    out: List[Tuple[str, str]] = []

    def walk(node: Any, path: str, depth: int) -> None:
        if len(out) >= limit or depth > 4:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k).startswith("_"):
                    continue
                walk(v, f"{path}.{k}" if path else str(k), depth + 1)
                if len(out) >= limit:
                    return
        elif isinstance(node, list):
            if node and all(not isinstance(i, (dict, list)) for i in node):
                out.append((path, clean_text(", ".join(str(i) for i in node[:10]) +
                                             (f" (+{len(node) - 10})" if len(node) > 10 else ""), 300)))
            elif node:
                out.append((path, f"{len(node)} item(s)"))
        elif node is not None and node != "":
            out.append((path, clean_text(node, 300)))

    walk(value, prefix, 0)
    return out


@dataclass
class Artifact:
    index: int
    data_type: str
    data: str
    message: str
    tags: List[str]
    tlp: Optional[int]
    iris_type: Optional[str]
    importable: bool
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def parse_artifacts(raw: Any, max_items: int = 1000) -> List[Artifact]:
    artifacts: List[Artifact] = []
    if not isinstance(raw, list):
        return artifacts
    seen = set()
    for index, item in enumerate(raw[:max_items]):
        if not isinstance(item, dict):
            continue
        data_type = clean_text(item.get("dataType"), 50).lower()
        if "attachment" in item and "data" not in item:
            continue    # file artifacts are not imported
        value = clean_text(item.get("data"), 8192).strip()
        tags = [clean_text(t, 100) for t in (item.get("tags") or []) if isinstance(t, (str, int))][:20]
        tlp = item.get("tlp") if isinstance(item.get("tlp"), int) else None
        iris_type = iris_type_for_artifact(data_type, value)
        importable, reason = True, ""
        if not value:
            importable, reason = False, "valor vazio"
        elif iris_type is None:
            importable, reason = False, f"tipo {data_type or '?'} não importável"
        else:
            try:
                value = normalize_value(data_type, value)
            except ObservableError as e:
                importable, reason = False, str(e)
        key = (data_type, value.lower())
        if importable and key in seen:
            continue
        seen.add(key)
        artifacts.append(Artifact(index=index, data_type=data_type, data=value,
                                  message=clean_text(item.get("message"), 500), tags=tags, tlp=tlp,
                                  iris_type=iris_type, importable=importable, reason=reason))
    return artifacts


def parse_operations(raw: Any) -> List[Dict[str, Any]]:
    ops: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return ops
    for index, op in enumerate(raw[:100]):
        if not isinstance(op, dict):
            continue
        op_type = clean_text(op.get("type"), 50)
        params = sanitize_json({k: v for k, v in op.items() if k != "type"})
        supported = op_type in SUPPORTED_OPERATIONS
        if op_type.startswith("AddTagTo") and not clean_text(params.get("tag"), 200).strip():
            supported = False
        if op_type == "CreateTask" and not clean_text(params.get("title"), 200).strip():
            supported = False
        ops.append({"index": index, "type": op_type, "params": params, "supported": supported, "applied": False})
    return ops


@dataclass
class ParsedReport:
    success: bool
    taxonomies: List[Dict[str, str]] = field(default_factory=list)
    verdict: Optional[str] = None
    highlights: List[Tuple[str, str]] = field(default_factory=list)
    full: Any = None
    full_truncated: bool = False
    artifacts: List[Artifact] = field(default_factory=list)
    operations: List[Dict[str, Any]] = field(default_factory=list)
    error_message: str = ""


def parse_report(report: Any, max_full_bytes: int = 2 * 1024 * 1024) -> ParsedReport:
    if not isinstance(report, dict):
        return ParsedReport(success=False, error_message="Relatório inválido retornado pelo Cortex")
    if report.get("success") is False or "errorMessage" in report:
        return ParsedReport(success=False, error_message=clean_text(report.get("errorMessage") or
                                                                    "O job falhou no Cortex", 2000))
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    taxonomies = [t for t in (normalize_taxonomy(x) for x in (summary.get("taxonomies") or [])[:200]) if t]
    full = sanitize_json(report.get("full"))
    stored_full, truncated = bounded_json(full, max_full_bytes)
    return ParsedReport(
        success=True,
        taxonomies=taxonomies,
        verdict=verdict(taxonomies),
        highlights=flatten_scalars(full),
        full=stored_full,
        full_truncated=truncated,
        artifacts=parse_artifacts(report.get("artifacts")),
        operations=parse_operations(report.get("operations")),
    )


_LEVEL_COLORS = {"info": "#1572e8", "safe": "#31ce36", "suspicious": "#ffad46", "malicious": "#f25961"}


def render_ioc_tab_html(entries: List[Dict[str, Any]]) -> str:
    """HTML summary for the IOC 'Cortex' tab. Every value is escaped; IRIS sanitises again on display."""
    rows = []
    for e in entries:
        taxes = " ".join(
            f'<span style="background:{_LEVEL_COLORS.get(t.get("level"), "#6c757d")};color:#fff;'
            f'padding:1px 6px;border-radius:3px;margin-right:4px">'
            f'{html.escape(t.get("namespace", ""))}:{html.escape(t.get("predicate", ""))}='
            f'{html.escape(t.get("value", ""))}</span>'
            for t in e.get("taxonomies", []))
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(e.get('worker_name', '')))}</td>"
            f"<td>{html.escape(str(e.get('finished_at', ''))[:19].replace('T', ' '))}</td>"
            f"<td>{html.escape(str(e.get('status', '')))}</td>"
            f"<td>{html.escape(str(e.get('verdict') or '-'))}</td>"
            f"<td>{taxes or '-'}</td>"
            f"<td>{html.escape(str(e.get('user_login', '')))}</td>"
            "</tr>")
    return ('<table class="table table-sm table-striped"><thead><tr><th>Analyzer</th><th>Data (UTC)</th>'
            '<th>Status</th><th>Veredito</th><th>Taxonomias</th><th>Executado por</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>")


def tlp_name(tlp: Optional[int]) -> str:
    return CORTEX_TLP_NAMES.get(tlp, str(tlp)) if tlp is not None else "-"
