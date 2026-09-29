import json

import pytest
import requests

from iris_cortex_module.core.client import (
    CortexAuthError, CortexBadResponse, CortexClient, CortexNotFound, CortexRequestError, CortexUnavailable,
    FileInput,
)
from tests.mock_cortex.server import FAKE_SECRET


def _client(url, key="test-key", **kw):
    return CortexClient(url, key, backoff=0.01, **kw)


def test_status_and_current_user(cortex):
    mock, url = cortex
    c = _client(url)
    assert c.status()["version"] == "4.1.0-1"
    assert c.current_user()["organization"] == "SOC"
    assert _client(url, "acme-key").current_user()["organization"] == "ACME"


def test_invalid_api_key(cortex):
    _, url = cortex
    with pytest.raises(CortexAuthError) as exc:
        _client(url, "wrong").current_user()
    assert "wrong" not in exc.value.detail and "inválida" in exc.value.user_message


def test_empty_api_key_is_refused_before_any_request():
    with pytest.raises(CortexAuthError):
        CortexClient("http://127.0.0.1:1", "")


def test_workers_never_expose_configuration(cortex):
    _, url = cortex
    c = _client(url)
    for workers in (c.analyzers_for_type("ip"), c.responders_for_type("thehive:case_artifact")):
        assert workers
        assert FAKE_SECRET not in json.dumps(workers)
        assert all("configuration" not in w for w in workers)
    names = {w["name"] for w in c.analyzers_for_type("ip")}
    assert {"VirusTotal_GetReport_3_1", "AbuseIPDB_1_0", "Shodan_Host_1_0"} <= names
    assert "FileInfo_8_0" not in names


def test_run_analyzer_json_and_job_lifecycle(cortex):
    mock, url = cortex
    c = _client(url)
    job = c.run_analyzer("abuseipdb", data_type="ip", data="185.220.101.10", tlp=1, pap=2, message="IRIS",
                         force=True)
    assert job["status"] == "Waiting"
    sent = json.loads(mock.requests[-1]["body"])
    assert sent == {"dataType": "ip", "tlp": 1, "pap": 2, "message": "IRIS", "parameters": {},
                    "data": "185.220.101.10"}
    assert "force=1" in mock.requests[-1]["path"]
    assert c.get_job(job["id"])["status"] == "InProgress"
    final, report = c.job_report(job["id"])
    assert final["status"] == "Success"
    assert report["summary"]["taxonomies"][0]["level"] == "malicious"
    assert c.job_statuses([job["id"]]) == {job["id"]: "Success"}


def test_run_analyzer_file_multipart(cortex):
    mock, url = cortex
    job = _client(url).run_analyzer("fileinfo", data_type="file",
                                    file=FileInput("sample.bin", b"MZ\x90\x00binary", "application/octet-stream"))
    assert job["dataType"] == "file"
    assert mock.files["sample.bin"] == b"MZ\x90\x00binary"
    assert mock.requests[-1]["content_type"].startswith("multipart/form-data")


def test_run_responder_sends_object(cortex):
    mock, url = cortex
    entity = {"_type": "case_artifact", "_id": "iris-ioc-1", "dataType": "ip", "data": "1.2.3.4"}
    job = _client(url).run_responder("block", data_type="thehive:case_artifact", data=entity)
    assert job["type"] == "responder"
    assert json.loads(mock.requests[-1]["body"])["data"] == entity


def test_incompatible_datatype_is_reported(cortex):
    _, url = cortex
    with pytest.raises(CortexRequestError) as exc:
        _client(url).run_analyzer("fileinfo", data_type="ip", data="1.1.1.1")
    assert "doesn't support ip" in exc.value.user_message


def test_unknown_worker_and_job(cortex):
    _, url = cortex
    with pytest.raises(CortexNotFound):
        _client(url).run_analyzer("nope", data_type="ip", data="1.1.1.1")
    with pytest.raises(CortexNotFound):
        _client(url).get_job("doesnotexist")


def test_path_injection_in_ids_is_refused(cortex):
    _, url = cortex
    with pytest.raises(CortexRequestError):
        _client(url).get_job("../user/current")
    with pytest.raises(CortexRequestError):
        _client(url).run_analyzer("vt/../../x", data_type="ip", data="1.1.1.1")


def test_get_retries_on_503_but_run_is_never_retried(cortex):
    mock, url = cortex
    c = _client(url, max_retries=3)
    job = c.run_analyzer("abuseipdb", data_type="ip", data="8.8.8.8")
    mock.fail_next_status = 2
    assert c.get_job(job["id"])["id"] == job["id"]          # 2 failures then success
    mock.fail_next_status = 10
    with pytest.raises(CortexUnavailable):
        c.get_job(job["id"])
    mock.fail_next_status = 0


def test_run_not_retried_on_connection_error():
    calls = []

    class Session(requests.Session):
        def request(self, *a, **kw):
            calls.append(a)
            raise requests.exceptions.ConnectionError("down")

    with pytest.raises(CortexUnavailable):
        CortexClient("http://cortex.invalid", "k", session=Session(), max_retries=5, backoff=0).run_analyzer(
            "vt", data_type="ip", data="1.1.1.1")
    assert len(calls) == 1


def test_connection_refused_is_unavailable():
    with pytest.raises(CortexUnavailable) as exc:
        CortexClient("http://127.0.0.1:1", "k", max_retries=1, backoff=0, timeout=2).status()
    assert "indisponível" in exc.value.user_message


def test_response_size_limit(cortex):
    _, url = cortex
    with pytest.raises(CortexBadResponse):
        _client(url, max_response_bytes=100).analyzers_for_type("ip")
