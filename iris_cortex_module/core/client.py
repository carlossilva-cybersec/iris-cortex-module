"""Cortex REST API client.

* Typed errors carrying a message for the analyst (``user_message``, Portuguese) and a technical
  ``detail`` for the audit log. The API key never appears in either.
* Read requests are retried with exponential backoff on network errors, 429 and 5xx. Job
  creation is never retried: a retry could start a second analysis or, worse, a second response
  action.
* Responses are read with a size cap and parsed as JSON only; workers and jobs are reduced to an
  allow-list of fields, so analyzer configuration (which holds third-party API keys when the
  Cortex user is orgAdmin) can never leak into IRIS.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote

import requests

USER_AGENT = "iris-cortex-module"
DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")

WORKER_FIELDS = ("id", "name", "version", "description", "dataTypeList", "author", "url", "license",
                 "workerDefinitionId", "analyzerDefinitionId", "rate", "rateUnit", "jobCache", "jobTimeout", "type")
JOB_FIELDS = ("id", "status", "workerId", "workerName", "workerDefinitionId", "analyzerId", "analyzerName",
              "responderId", "responderName", "dataType", "tlp", "pap", "message", "errorMessage", "label",
              "startDate", "endDate", "date", "createdAt", "updatedAt", "createdBy", "organization", "type")

JOB_WAITING = "Waiting"
JOB_IN_PROGRESS = "InProgress"
JOB_SUCCESS = "Success"
JOB_FAILURE = "Failure"
JOB_DELETED = "Deleted"
FINAL_JOB_STATUSES = (JOB_SUCCESS, JOB_FAILURE, JOB_DELETED)


class CortexError(Exception):
    user_message = "Erro ao comunicar com o Cortex"
    retryable = False

    def __init__(self, detail: str = "", status_code: Optional[int] = None, user_message: Optional[str] = None):
        super().__init__(user_message or self.user_message)
        if user_message:
            self.user_message = user_message
        self.detail = (detail or "")[:2000]
        self.status_code = status_code


class CortexUnavailable(CortexError):
    user_message = "Cortex indisponível. Tente novamente em instantes."
    retryable = True


class CortexTimeout(CortexError):
    user_message = "O Cortex não respondeu dentro do tempo limite."
    retryable = True


class CortexTLSError(CortexError):
    user_message = "Falha na validação TLS do Cortex (certificado inválido ou CA não confiável)."


class CortexAuthError(CortexError):
    user_message = "API key do Cortex inválida, expirada ou não configurada."


class CortexPermissionError(CortexError):
    user_message = "O usuário do Cortex não tem permissão para esta operação."


class CortexNotFound(CortexError):
    user_message = "Recurso não encontrado no Cortex (analyzer, responder ou job inexistente ou desativado)."


class CortexRateLimited(CortexError):
    user_message = "Limite de requisições do Cortex atingido. Tente novamente mais tarde."
    retryable = True


class CortexRequestError(CortexError):
    user_message = "O Cortex recusou a requisição."


class CortexBadResponse(CortexError):
    user_message = "Resposta inesperada do Cortex."


@dataclass
class FileInput:
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


def _check_id(value: str, what: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise CortexRequestError(f"invalid {what} id", user_message=f"Identificador de {what} inválido.")
    return value


def _pick(obj: Any, fields: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    return {k: obj[k] for k in fields if k in obj}


def clean_worker(worker: Any) -> Dict[str, Any]:
    data = _pick(worker, WORKER_FIELDS)
    if "id" not in data and isinstance(worker, dict) and "_id" in worker:
        data["id"] = worker["_id"]
    if not isinstance(data.get("dataTypeList"), list):
        data["dataTypeList"] = []
    return data


def clean_job(job: Any) -> Dict[str, Any]:
    data = _pick(job, JOB_FIELDS)
    if "id" not in data and isinstance(job, dict) and "_id" in job:
        data["id"] = job["_id"]
    return data


class CortexClient:
    def __init__(self, base_url: str, api_key: Optional[str], *, verify: Any = True, timeout: float = 30,
                 max_retries: int = 3, backoff: float = 1.0, session: Optional[requests.Session] = None,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES, proxies: Optional[Mapping[str, str]] = None):
        if not api_key:
            raise CortexAuthError("API key is empty")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.backoff = backoff
        self.max_response_bytes = max_response_bytes
        self.session = session or requests.Session()
        self.session.verify = verify
        if proxies:
            self.session.proxies.update(proxies)
        self.session.headers.update({"Authorization": f"Bearer {api_key}", "User-Agent": USER_AGENT,
                                     "Accept": "application/json"})

    @classmethod
    def from_settings(cls, settings, customer_name: Optional[str] = None, **kwargs) -> "CortexClient":
        verify: Any = settings.verify_tls
        if settings.verify_tls and settings.ca_file:
            verify = settings.ca_file
        return cls(settings.cortex_url, settings.api_key(customer_name), verify=verify, timeout=settings.timeout,
                   max_retries=settings.max_retries, **kwargs)

    # ------------------------------------------------------------------ transport

    def _read_body(self, response: requests.Response) -> bytes:
        chunks: List[bytes] = []
        total = 0
        for chunk in response.iter_content(64 * 1024):
            total += len(chunk)
            if total > self.max_response_bytes:
                response.close()
                raise CortexBadResponse(f"response larger than {self.max_response_bytes} bytes",
                                        user_message="Resposta do Cortex excede o tamanho máximo permitido.")
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _error_message(body: bytes) -> str:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
            if isinstance(data, dict):
                return str(data.get("message") or data.get("type") or "")[:500]
        except ValueError:
            pass
        return body[:300].decode("utf-8", "replace")

    def _raise_for_status(self, response: requests.Response, body: bytes) -> None:
        code = response.status_code
        if code < 400:
            return
        message = self._error_message(body)
        detail = f"HTTP {code} {response.request.method} {response.url.split('?')[0]}: {message}"
        if code == 401:
            raise CortexAuthError(detail, code)
        if code == 403:
            raise CortexPermissionError(detail, code)
        if code == 404:
            raise CortexNotFound(detail, code)
        if code == 429:
            raise CortexRateLimited(detail, code)
        if code >= 500:
            raise CortexUnavailable(detail, code, user_message="O Cortex retornou um erro interno. "
                                                               "Tente novamente em instantes.")
        raise CortexRequestError(detail, code, user_message=f"O Cortex recusou a requisição: {message}"
                                 if message else None)

    def _request(self, method: str, path: str, *, retry: bool, **kwargs) -> Any:
        url = f"{self.base_url}{path}"
        attempts = (self.max_retries + 1) if retry else 1
        last_error: Optional[CortexError] = None
        for attempt in range(attempts):
            if attempt:
                time.sleep(min(self.backoff * (2 ** (attempt - 1)), 30))
            try:
                with self.session.request(method, url, timeout=self.timeout, stream=True,
                                          allow_redirects=False, **kwargs) as response:
                    body = self._read_body(response)
                    if 300 <= response.status_code < 400:
                        raise CortexBadResponse(f"unexpected redirect HTTP {response.status_code} to "
                                                f"{response.headers.get('Location', '?')}",
                                                user_message="O Cortex respondeu com um redirecionamento "
                                                             "inesperado. Verifique a URL configurada.")
                    self._raise_for_status(response, body)
            except requests.exceptions.SSLError as e:
                raise CortexTLSError(f"{e.__class__.__name__}: {e}")
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
                last_error = CortexTimeout(f"{e.__class__.__name__} after {self.timeout}s")
            except requests.exceptions.ConnectionError as e:
                last_error = CortexUnavailable(f"{e.__class__.__name__}: {str(e)[:300]}")
            except requests.exceptions.RequestException as e:
                raise CortexUnavailable(f"{e.__class__.__name__}: {str(e)[:300]}")
            except CortexError as e:
                if not e.retryable:
                    raise
                last_error = e
            else:
                if not body:
                    return None
                try:
                    return json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as e:
                    raise CortexBadResponse(f"invalid JSON from {path}: {e}")
        raise last_error  # type: ignore[misc]

    def _get(self, path: str, **kwargs) -> Any:
        return self._request("GET", path, retry=True, **kwargs)

    # ------------------------------------------------------------------ API

    def status(self) -> Dict[str, Any]:
        data = self._get("/api/status")
        if not isinstance(data, dict):
            raise CortexBadResponse("status is not an object")
        versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
        return {"version": versions.get("Cortex"), "versions": {k: str(v) for k, v in versions.items()}}

    def current_user(self) -> Dict[str, Any]:
        data = self._get("/api/user/current")
        if not isinstance(data, dict):
            raise CortexBadResponse("user is not an object")
        return {"id": data.get("id") or data.get("_id"), "name": data.get("name"),
                "organization": data.get("organization"), "roles": list(data.get("roles") or [])}

    def _workers_for_type(self, kind: str, data_type: str) -> List[Dict[str, Any]]:
        data = self._get(f"/api/{kind}/type/{quote(data_type, safe=':')}")
        if not isinstance(data, list):
            raise CortexBadResponse(f"{kind} list is not an array")
        return [clean_worker(w) for w in data if isinstance(w, dict)]

    def analyzers_for_type(self, data_type: str) -> List[Dict[str, Any]]:
        return self._workers_for_type("analyzer", data_type)

    def responders_for_type(self, data_type: str) -> List[Dict[str, Any]]:
        return self._workers_for_type("responder", data_type)

    def run_analyzer(self, analyzer_id: str, *, data_type: str, data: Optional[str] = None,
                     file: Optional[FileInput] = None, tlp: int = 2, pap: int = 2, message: str = "",
                     parameters: Optional[Mapping[str, Any]] = None, label: Optional[str] = None,
                     force: bool = False) -> Dict[str, Any]:
        path = f"/api/analyzer/{quote(_check_id(analyzer_id, 'analyzer'))}/run"
        attributes: Dict[str, Any] = {"dataType": data_type, "tlp": int(tlp), "pap": int(pap),
                                      "message": message or "", "parameters": dict(parameters or {})}
        if label:
            attributes["label"] = label
        params = {"force": "1"} if force else None
        if data_type == "file":
            if file is None:
                raise CortexRequestError("file analyzer without file")
            job = self._request("POST", path, retry=False, params=params,
                                files={"data": (file.filename, file.content, file.content_type)},
                                data={"_json": json.dumps(attributes)})
        else:
            attributes["data"] = data
            job = self._request("POST", path, retry=False, params=params, json=attributes)
        return self._job_or_error(job)

    def run_responder(self, responder_id: str, *, data_type: str, data: Mapping[str, Any], tlp: int = 2,
                      pap: int = 2, message: str = "", parameters: Optional[Mapping[str, Any]] = None,
                      label: Optional[str] = None) -> Dict[str, Any]:
        path = f"/api/responder/{quote(_check_id(responder_id, 'responder'))}/run"
        body: Dict[str, Any] = {"dataType": data_type, "data": dict(data), "tlp": int(tlp), "pap": int(pap),
                                "message": message or "", "parameters": dict(parameters or {})}
        if label:
            body["label"] = label
        return self._job_or_error(self._request("POST", path, retry=False, json=body))

    @staticmethod
    def _job_or_error(job: Any) -> Dict[str, Any]:
        cleaned = clean_job(job)
        if not cleaned.get("id"):
            raise CortexBadResponse("job creation returned no job id")
        return cleaned

    def get_job(self, job_id: str) -> Dict[str, Any]:
        job = self._get(f"/api/job/{quote(_check_id(job_id, 'job'))}")
        cleaned = clean_job(job)
        if not cleaned.get("id"):
            raise CortexBadResponse("job without id")
        return cleaned

    def job_statuses(self, job_ids: Sequence[str]) -> Dict[str, str]:
        ids = [_check_id(j, "job") for j in job_ids]
        if not ids:
            return {}
        data = self._request("POST", "/api/job/status", retry=True, json={"jobIds": ids})
        if not isinstance(data, dict):
            raise CortexBadResponse("job status is not an object")
        return {str(k): str(v) for k, v in data.items()}

    def job_report(self, job_id: str) -> Tuple[Dict[str, Any], Any]:
        """Return (job, report). report is a dict for finished jobs, a string while running."""
        data = self._get(f"/api/job/{quote(_check_id(job_id, 'job'))}/report")
        if not isinstance(data, dict):
            raise CortexBadResponse("report is not an object")
        return clean_job(data), data.get("report")
