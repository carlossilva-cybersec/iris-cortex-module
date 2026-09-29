"""Minimal Cortex 4.x API simulator for tests (stdlib only).

Implements the endpoints used by iris_cortex_module with the response shapes of Cortex 4.1:
status, current user, analyzers/responders by data type, job creation (JSON and multipart),
job status, batch status and reports. Jobs go Waiting -> InProgress -> Success/Failure on
successive reads. Workers deliberately include a ``configuration`` object with a fake secret so
tests can check that the client never lets it through.

Run standalone:  python server.py --port 9001 --api-key test-key
Inspect:         GET /_mock/requests   (every request received, bodies included)
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import uuid
from email import policy as _email_policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

FAKE_SECRET = "VT-API-KEY-SHOULD-NEVER-LEAK"


def parse_multipart(content_type: str, body: bytes) -> Dict[str, Any]:
    """Return {field: (filename, bytes) or str} for a multipart/form-data body."""
    msg = BytesParser(policy=_email_policy.default).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body)
    fields: Dict[str, Any] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        fields[name] = (filename, payload) if filename is not None else payload.decode("utf-8")
    return fields


def _worker(wid, name, version, data_types, description, wtype="analyzer"):
    return {"id": wid, "_id": wid, "name": name, "version": version, "description": description,
            "dataTypeList": data_types, "author": "TheHive-Project", "url": "https://github.com/TheHive-Project",
            "license": "AGPL-V3", "workerDefinitionId": name, "type": wtype, "rate": 500, "rateUnit": "Day",
            "jobCache": 10, "configuration": {"key": FAKE_SECRET, "check_tlp": True, "max_tlp": 2}}


ANALYZERS = [
    _worker("vt", "VirusTotal_GetReport_3_1", "3.1", ["domain", "fqdn", "ip", "url", "hash", "file"],
            "Get the latest VirusTotal report for a file, hash, domain or an IP address."),
    _worker("abuseipdb", "AbuseIPDB_1_0", "1.0", ["ip"], "Determine whether an IP was reported or not as malicious by AbuseIPDB"),
    _worker("shodan", "Shodan_Host_1_0", "1.0", ["ip"], "Retrieve Shodan information on an IP address"),
    _worker("misp", "MISP_2_1", "2.1", ["domain", "fqdn", "ip", "url", "hash", "mail", "filename", "other"],
            "Query multiple MISP instances for events containing an observable."),
    _worker("fileinfo", "FileInfo_8_0", "8.0", ["file"], "Parse files in several formats"),
    _worker("crash", "Crashy_1_0", "1.0", ["ip", "domain"], "Always fails (test analyzer)"),
]
RESPONDERS = [
    _worker("mailer", "Mailer_1_0", "1.0", ["thehive:case", "thehive:alert", "thehive:case_artifact"],
            "Send an email with information from a TheHive case or alert", "responder"),
    _worker("block", "PaloAltoNGFW_block_ip_1_0", "1.0", ["thehive:case_artifact"],
            "Block an IP address on PaloAlto NGFW", "responder"),
    _worker("misp_export", "MISP_Export_1_0", "1.0", ["thehive:case_artifact"],
            "Add an observable to a MISP event", "responder"),
]


def _report_for(worker: Dict[str, Any], data_type: str, data: Optional[str]) -> Dict[str, Any]:
    name = worker["name"]
    if worker["type"] == "responder":
        ops = [{"type": "AddTagToArtifact", "tag": f"{name}:done"}]
        if "block" in name.lower():
            ops.append({"type": "CreateTask", "title": "Validar bloqueio", "description": "Confirmar regra no firewall"})
        return {"summary": {"taxonomies": []}, "full": {"message": f"{name} executed", "data": data},
                "success": True, "artifacts": [], "operations": ops}
    level = "malicious" if data in ("185.220.101.10", "malicious-domain.com") else "safe"
    full = {
        "positives": 12 if level == "malicious" else 0, "total": 70,
        "scan_date": "2026-09-29 10:34:22",
        "asn": 205100, "country": "DE", "as_owner": "F3 Netze e.V.",
        "html_payload": "<script>alert('xss-from-analyzer')</script>",
        "resolutions": [{"hostname": "evil.example", "last_resolved": "2026-09-01"}],
        "nested": {"a": {"b": {"c": "deep"}}},
    }
    artifacts = [
        {"dataType": "domain", "data": "evil.example", "message": "Resolved hostname", "tags": ["vt"], "tlp": 2},
        {"dataType": "ip", "data": "203.0.113.7", "message": "Related IP", "tags": [], "tlp": 2},
        {"dataType": "hash", "data": "44d88612fea8a8f36de82e1278abb02f", "message": "Downloaded sample", "tags": []},
        {"dataType": "url", "data": "javascript:alert(1)", "message": "bogus url", "tags": []},
        {"dataType": "domain", "data": "evil.example", "message": "duplicate", "tags": []},
    ]
    return {
        "summary": {"taxonomies": [
            {"level": level, "namespace": name.split("_")[0], "predicate": "Score",
             "value": f"{full['positives']}/{full['total']}"},
            {"level": "info", "namespace": name.split("_")[0], "predicate": "Country", "value": "DE"},
        ]},
        "full": full, "success": True, "artifacts": artifacts, "operations": [],
    }


class MockCortex:
    def __init__(self, api_keys: Dict[str, str], steps_to_finish: int = 2):
        self.api_keys = api_keys                # key -> organisation
        self.steps_to_finish = steps_to_finish
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.requests: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.files: Dict[str, bytes] = {}     # uploaded files, by name
        self.fail_next_status = 0               # simulate 503 on the next N GET /api/job/*

    def worker(self, wid: str, wtype: str) -> Optional[Dict[str, Any]]:
        pool = ANALYZERS if wtype == "analyzer" else RESPONDERS
        return next((w for w in pool if w["id"] == wid), None)

    def create_job(self, worker, data_type, data, attributes, org, filename=None):
        jid = uuid.uuid4().hex[:20]
        job = {"id": jid, "_id": jid, "status": "Waiting", "workerId": worker["id"], "workerName": worker["name"],
               "workerDefinitionId": worker["name"], "dataType": data_type, "tlp": attributes.get("tlp", 2),
               "pap": attributes.get("pap", 2), "message": attributes.get("message", ""),
               "parameters": json.dumps(attributes.get("parameters") or {}), "type": worker["type"],
               "organization": org, "startDate": int(time.time() * 1000), "createdAt": int(time.time() * 1000),
               "createdBy": "iris", "_reads": 0, "_data": data, "_filename": filename}
        if data_type != "file":
            job["data"] = data if isinstance(data, str) else json.dumps(data)
        with self.lock:
            self.jobs[jid] = job
        return job

    def advance(self, job):
        job["_reads"] += 1
        if job["status"] in ("Success", "Failure"):
            return
        if job["_reads"] >= self.steps_to_finish:
            job["status"] = "Failure" if job["workerId"] == "crash" else "Success"
            job["endDate"] = int(time.time() * 1000)
            if job["status"] == "Failure":
                job["errorMessage"] = "Invalid API key for upstream service"
        elif job["_reads"] >= 1:
            job["status"] = "InProgress"


def public_job(job):
    return {k: v for k, v in job.items() if not k.startswith("_")}


def make_handler(mock: MockCortex):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MockCortex/4.1"

        def log_message(self, *args):
            pass

        def _send(self, code: int, payload: Any):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self) -> Optional[str]:
            header = self.headers.get("Authorization", "")
            key = header[7:] if header.startswith("Bearer ") else ""
            org = mock.api_keys.get(key)
            if not org:
                self._send(401, {"type": "AuthenticationError", "message": "Authentication failure"})
            return org

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def _record(self, body: bytes):
            with mock.lock:
                mock.requests.append({"method": self.command, "path": self.path,
                                      "content_type": self.headers.get("Content-Type", ""),
                                      "body": body.decode("utf-8", "replace")[:100000]})

        def do_GET(self):
            self._record(b"")
            path = self.path.split("?")[0]
            if path == "/_mock/requests":
                return self._send(200, mock.requests)
            if path == "/api/status":
                return self._send(200, {"versions": {"Cortex": "4.1.0-1", "Elastic4Play": "1.13.6"},
                                        "config": {"authType": ["key"], "capabilities": ["authByKey"]}})
            org = self._auth()
            if not org:
                return
            if path == "/api/user/current":
                return self._send(200, {"id": "iris", "name": "IRIS integration", "organization": org,
                                        "roles": ["read", "analyze"], "status": "Ok"})
            for kind, pool in (("analyzer", ANALYZERS), ("responder", RESPONDERS)):
                prefix = f"/api/{kind}/type/"
                if path.startswith(prefix):
                    dt = path[len(prefix):].replace("%3A", ":")
                    return self._send(200, [w for w in pool if dt in w["dataTypeList"]])
            if path.startswith("/api/job/"):
                if mock.fail_next_status > 0:
                    mock.fail_next_status -= 1
                    return self._send(503, {"type": "ServiceUnavailable", "message": "busy"})
                parts = path.split("/")
                job = mock.jobs.get(parts[3])
                if not job or job["organization"] != org:
                    return self._send(404, {"type": "NotFoundError", "message": "job not found"})
                if len(parts) == 4:
                    mock.advance(job)
                    return self._send(200, public_job(job))
                if parts[4] == "report":
                    mock.advance(job)
                    out = public_job(job)
                    if job["status"] == "Success":
                        worker = mock.worker(job["workerId"], job["type"])
                        out["report"] = _report_for(worker, job["dataType"], job.get("_data") if
                                                    isinstance(job.get("_data"), str) else None)
                    elif job["status"] == "Failure":
                        out["report"] = {"errorMessage": job["errorMessage"], "input": None, "success": False}
                    else:
                        out["report"] = "Running" if job["status"] == "InProgress" else "Waiting"
                    return self._send(200, out)
            return self._send(404, {"type": "NotFoundError", "message": f"{path} not found"})

        def do_POST(self):
            body = self._body()
            self._record(body)
            org = self._auth()
            if not org:
                return
            path = self.path.split("?")[0]
            if path == "/api/job/status":
                ids = json.loads(body or b"{}").get("jobIds", [])
                return self._send(200, {j: mock.jobs[j]["status"] for j in ids if j in mock.jobs})
            for kind in ("analyzer", "responder"):
                prefix = f"/api/{kind}/"
                if path.startswith(prefix) and path.endswith("/run"):
                    worker = mock.worker(path[len(prefix):-4], kind)
                    if not worker:
                        return self._send(404, {"type": "NotFoundError", "message": f"{kind} not found"})
                    ctype = self.headers.get("Content-Type", "")
                    filename = None
                    if ctype.startswith("multipart/form-data"):
                        form = parse_multipart(ctype, body)
                        attributes = json.loads(form["_json"])
                        filename, content = form["data"]
                        data = None
                        with mock.lock:
                            mock.files[filename] = content
                    else:
                        attributes = json.loads(body or b"{}")
                        data = attributes.get("data")
                    data_type = attributes.get("dataType")
                    if not data_type:
                        return self._send(400, {"type": "AttributeCheckingError", "message": "dataType is missing"})
                    if data_type not in worker["dataTypeList"]:
                        return self._send(400, {"type": "BadRequest",
                                                "message": f"{worker['name']} doesn't support {data_type}"})
                    job = mock.create_job(worker, data_type, data, attributes, org, filename)
                    return self._send(200, public_job(job))
            return self._send(404, {"type": "NotFoundError", "message": f"{path} not found"})

    return Handler


def start(port: int = 0, api_keys: Optional[Dict[str, str]] = None, steps_to_finish: int = 2):
    """Start in a background thread. Returns (server, mock, base_url)."""
    mock = MockCortex(api_keys or {"test-key": "SOC"}, steps_to_finish)
    server = ThreadingHTTPServer(("127.0.0.1" if port == 0 else "0.0.0.0", port), make_handler(mock))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, mock, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9001)
    parser.add_argument("--api-key", action="append", default=[],
                        help="key[:organisation], repeatable")
    args = parser.parse_args()
    keys = {}
    for item in args.api_key or ["test-key"]:
        key, _, org = item.partition(":")
        keys[key] = org or "SOC"
    mock = MockCortex(keys)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(mock))
    print(f"Mock Cortex listening on :{args.port}", flush=True)
    httpd.serve_forever()
