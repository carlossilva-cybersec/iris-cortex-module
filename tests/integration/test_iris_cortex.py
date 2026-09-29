"""End-to-end tests: live IRIS v2.4.29 + iris_cortex_module + the Cortex simulator.

Prerequisites (see README, "Testes de integração"):
  * stack started with docker/docker-compose.cortex.yml and --profile cortextest (mock-cortex running)
  * IRIS_CORTEX_MOCK_API_KEY=test-key in iris-web/.env (app and worker recreated after adding it)
  * module registered and enabled

The suite points the module at the simulator for its duration (cortex_url, API key variable,
poll interval) and restores the previous configuration afterwards, so a real Cortex configured
for daily use is left untouched.

Environment:
  IRIS_URL, IRIS_API_KEY (administrator), IRIS_CASE_ID (default 1), IRIS_ALERT_ID (optional),
  MOCK_CORTEX_URL (default http://127.0.0.1:9001), IRIS_VERIFY_TLS=false for the dev certificate.

The tests create IOCs, an evidence, a user and change module parameters; parameters are restored
at the end.
"""
import json
import os
import time
import uuid

import pytest

requests = pytest.importorskip("requests")

IRIS_URL = os.getenv("IRIS_URL", "").rstrip("/")
API_KEY = os.getenv("IRIS_API_KEY")
CASE_ID = int(os.getenv("IRIS_CASE_ID", "1"))
ALERT_ID = os.getenv("IRIS_ALERT_ID")
MOCK = os.getenv("MOCK_CORTEX_URL", "http://127.0.0.1:9011").rstrip("/")
MOCK_FROM_IRIS = os.getenv("MOCK_CORTEX_URL_FROM_IRIS", "http://mock-cortex:9001")
MOCK_KEY_ENV = os.getenv("MOCK_CORTEX_KEY_ENV", "IRIS_CORTEX_MOCK_API_KEY")
VERIFY = os.getenv("IRIS_VERIFY_TLS", "true").lower() != "false"
FAKE_SECRET = "VT-API-KEY-SHOULD-NEVER-LEAK"

pytestmark = pytest.mark.skipif(not (IRIS_URL and API_KEY), reason="IRIS_URL / IRIS_API_KEY not set")


def session(key=API_KEY):
    s = requests.Session()
    s.verify = VERIFY
    s.headers["Authorization"] = f"Bearer {key}"
    return s


def js(r):
    return json.loads(r.text, strict=False)


def ok(r):
    assert r.status_code == 200, r.text[:500]
    data = js(r)
    assert data["status"] == "success", data
    return data["data"]


def wait_final(s, execution_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = ok(s.get(f"{IRIS_URL}/cortex-module/executions/{execution_id}"))
        if data["final"]:
            return data
        time.sleep(1)
    raise AssertionError(f"execution {execution_id} not final after {timeout}s")


def mock_requests():
    return requests.get(f"{MOCK}/_mock/requests", timeout=5).json()


@pytest.fixture(scope="module")
def iris():
    s = session()
    types = {t["type_name"]: t["type_id"] for t in ok(s.get(f"{IRIS_URL}/manage/ioc-types/list"))}
    tlps = {t["tlp_name"]: t["tlp_id"] for t in ok(s.get(f"{IRIS_URL}/manage/tlp/list"))}
    modules = ok(s.get(f"{IRIS_URL}/manage/modules/list"))
    module_id = next(m["id"] for m in modules if m["module_human_name"] == "IrisCortex")
    original = ok(s.get(f"{IRIS_URL}/manage/modules/export-config/{module_id}"))["module_configuration"]
    suffix = uuid.uuid4().hex[:6]
    ok(s.post(f"{IRIS_URL}/manage/modules/import-config/{module_id}", json={"module_configuration": [
        {"param_name": "cortex_url", "value": MOCK_FROM_IRIS},
        {"param_name": "cortex_api_key_env", "value": MOCK_KEY_ENV},
        {"param_name": "poll_interval", "value": "3"},
        {"param_name": "customer_api_keys", "value": "{}"}]}))

    def add_ioc(value, type_name, tlp):
        r = s.post(f"{IRIS_URL}/case/ioc/add?cid={CASE_ID}", json={
            "ioc_value": value, "ioc_type_id": types[type_name], "ioc_tlp_id": tlps[tlp],
            "ioc_description": "cortex integration test", "ioc_tags": "it"})
        return ok(r)["ioc_id"]

    data = {
        "s": s, "types": types, "tlps": tlps, "module_id": module_id, "suffix": suffix,
        "ip": add_ioc("185.220.101.10", "ip-dst", "green"),
        "red": add_ioc(f"10.66.{int(suffix[:2], 16)}.{int(suffix[2:4], 16)}", "ip-dst", "red"),
        "composite": add_ioc(f"invoice-{suffix}.exe|{'ab' * 32}", "filename|sha256", "amber"),
    }
    ev = s.post(f"{IRIS_URL}/case/evidences/add?cid={CASE_ID}", json={
        "filename": f"dump-{suffix}.raw", "file_size": 1024, "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "file_description": "memory dump", "type_id": 1})
    data["evidence"] = ok(ev)["id"]
    yield data
    s.post(f"{IRIS_URL}/manage/modules/import-config/{module_id}", json={"module_configuration": original})


def set_params(iris, **params):
    ok(iris["s"].post(f"{IRIS_URL}/manage/modules/import-config/{iris['module_id']}", json={
        "module_configuration": [{"param_name": k, "value": v} for k, v in params.items()]}))


def catalog(s, kind, oid, ctype="case", cid=CASE_ID):
    return s.get(f"{IRIS_URL}/cortex-module/observables/{kind}/{oid}",
                 params={"context_type": ctype, "context_id": cid})


def run(s, kind, oid, analyzers, ctype="case", cid=CASE_ID, index=0):
    return s.post(f"{IRIS_URL}/cortex-module/analyzers/run", json={
        "kind": kind, "object_id": oid, "context_type": ctype, "context_id": cid,
        "observable_index": index, "analyzer_ids": analyzers})


# --------------------------------------------------------------------------- tests

def test_status_reachable_and_no_secret(iris):
    r = iris["s"].get(f"{IRIS_URL}/cortex-module/status")
    data = ok(r)
    assert data["reachable"] and data["version"] == "4.1.0-1" and data["organization"] == "SOC"
    assert FAKE_SECRET not in r.text


def test_unauthenticated_is_rejected():
    r = requests.get(f"{IRIS_URL}/cortex-module/status", verify=VERIFY, allow_redirects=False, timeout=10)
    assert r.status_code in (401, 302)


def test_catalog_lists_compatible_workers_without_configuration(iris):
    r = catalog(iris["s"], "ioc", iris["ip"])
    data = ok(r)
    assert data["object"]["observables"][0] == {**data["object"]["observables"][0], "data_type": "ip",
                                                 "data": "185.220.101.10", "tlp": 1}
    names = {a["name"] for a in data["analyzers"]}
    assert {"VirusTotal_GetReport_3_1", "AbuseIPDB_1_0", "Shodan_Host_1_0", "MISP_2_1"} <= names
    assert "FileInfo_8_0" not in names
    responders = {x["name"]: x for x in data["responders"]}
    assert responders["PaloAltoNGFW_block_ip_1_0"]["privileged"] is True
    assert responders["Mailer_1_0"]["privileged"] is False
    assert FAKE_SECRET not in r.text and '"configuration"' not in r.text


def test_composite_ioc_yields_two_observables(iris):
    obs = ok(catalog(iris["s"], "ioc", iris["composite"]))["object"]["observables"]
    assert [o["data_type"] for o in obs] == ["filename", "hash"]


def test_evidence_is_analysed_by_hash_and_name(iris):
    data = ok(catalog(iris["s"], "evidence", iris["evidence"]))
    assert [o["data_type"] for o in data["object"]["observables"]] == ["hash", "filename"]


def test_object_outside_context_is_refused(iris):
    assert catalog(iris["s"], "ioc", iris["ip"], ctype="case", cid=999999).status_code == 403
    assert catalog(iris["s"], "ioc", 99999999).status_code == 404
    if ALERT_ID:
        assert catalog(iris["s"], "ioc", iris["ip"], ctype="alert", cid=int(ALERT_ID)).status_code == 404


def test_analyzers_run_async_and_record_everything(iris):
    s = iris["s"]
    started = ok(run(s, "ioc", iris["ip"], ["abuseipdb", "crash"]))
    assert {e["status"] for e in started} <= {"waiting", "in_progress"}
    sent = [json.loads(r["body"]) for r in mock_requests() if r["path"].startswith("/api/analyzer/abuseipdb/run")][-1]
    assert sent["data"] == "185.220.101.10" and sent["tlp"] == 1 and sent["dataType"] == "ip"

    results = {e["worker_name"]: wait_final(s, e["id"]) for e in started}
    ok_run, failed = results["AbuseIPDB_1_0"], results["Crashy_1_0"]
    assert ok_run["status"] == "success" and ok_run["verdict"] == "malicious"
    assert ok_run["taxonomies"][0]["value"] == "12/70"
    assert failed["status"] == "failure" and "Invalid API key" in failed["error_message"]

    report = ok(s.get(f"{IRIS_URL}/cortex-module/executions/{ok_run['id']}/report"))
    assert report["report"]["html_payload"] == "<script>alert('xss-from-analyzer')</script>"   # data, never HTML

    timeline = ok(s.get(f"{IRIS_URL}/case/timeline/events/list", params={"cid": CASE_ID}))["timeline"]
    titles = [e["event_title"] for e in timeline]
    assert "Cortex Analyzer executed: AbuseIPDB_1_0 on 185.220.101.10" in titles
    assert "Cortex Analyzer executed: Crashy_1_0 on 185.220.101.10" in titles
    event = next(e for e in timeline if e["event_title"] == "Cortex Analyzer executed: AbuseIPDB_1_0 on 185.220.101.10")
    assert "Executed by: administrator" in event["event_content"] and "Verdict: malicious" in event["event_content"]

    ioc = ok(s.get(f"{IRIS_URL}/case/ioc/{iris['ip']}", params={"cid": CASE_ID}))
    tab = ioc["custom_attributes"]["Cortex"]["Resultados"]
    assert tab["type"] == "html" and "AbuseIPDB_1_0" in tab["value"] and "<script" not in tab["value"]
    iris["analysis"] = ok_run["id"]


def test_import_selected_artifacts(iris):
    s = iris["s"]
    execution = ok(s.get(f"{IRIS_URL}/cortex-module/executions/{iris['analysis']}"))
    arts = {a["data"]: a for a in execution["artifacts"]}
    assert not arts["javascript:alert(1)"]["importable"]
    pick = [arts["evil.example"]["index"], arts["203.0.113.7"]["index"]]
    result = ok(s.post(f"{IRIS_URL}/cortex-module/executions/{iris['analysis']}/import", json={"indexes": pick}))
    assert [r["ok"] for r in result["results"]] == [True, True]
    again = ok(s.post(f"{IRIS_URL}/cortex-module/executions/{iris['analysis']}/import", json={"indexes": pick}))
    assert {r["message"] for r in again["results"]} == {"Já importado"}
    bogus = ok(s.post(f"{IRIS_URL}/cortex-module/executions/{iris['analysis']}/import",
                      json={"indexes": [arts["javascript:alert(1)"]["index"]]}))
    assert not bogus["results"][0]["ok"]
    iocs = ok(s.get(f"{IRIS_URL}/case/ioc/list", params={"cid": CASE_ID}))["ioc"]
    imported = next(i for i in iocs if i["ioc_value"] == "evil.example")
    assert "cortex" in imported["ioc_tags"] and "AbuseIPDB_1_0" in imported["ioc_description"]


def test_tlp_red_is_never_sent(iris):
    before = len(mock_requests())
    r = run(iris["s"], "ioc", iris["red"], ["abuseipdb"])
    assert r.status_code == 403 and "TLP:RED" in js(r)["message"]
    after = [x for x in mock_requests()[before:] if "/run" in x["path"]]
    assert after == []
    blocked = ok(catalog(iris["s"], "ioc", iris["red"]))["analyzers"]
    assert blocked and not any(a["allowed"] for a in blocked)


def test_incompatible_analyzer_is_refused(iris):
    r = run(iris["s"], "ioc", iris["ip"], ["fileinfo"])
    assert r.status_code == 400 and "incompatível" in js(r)["message"]


def test_responder_requires_confirmation_and_is_idempotent(iris):
    s = iris["s"]
    body = {"kind": "ioc", "object_id": iris["ip"], "context_type": "case", "context_id": CASE_ID,
            "responder_id": "block", "request_uuid": str(uuid.uuid4())}
    assert s.post(f"{IRIS_URL}/cortex-module/responders/run", json=body).status_code == 400
    execution = ok(s.post(f"{IRIS_URL}/cortex-module/responders/run", json={**body, "confirm": True}))
    assert execution["privileged"] is True
    assert s.post(f"{IRIS_URL}/cortex-module/responders/run", json={**body, "confirm": True}).status_code == 409

    sent = [json.loads(r["body"]) for r in mock_requests() if r["path"].startswith("/api/responder/block/run")][-1]
    assert sent["dataType"] == "thehive:case_artifact"
    assert sent["data"]["_type"] == "case_artifact" and sent["data"]["data"] == "185.220.101.10"
    assert sent["data"]["case"]["caseId"] == CASE_ID

    final = wait_final(s, execution["id"])
    assert final["status"] == "success"
    ops = {o["type"]: o for o in final["operations"]}
    ok(s.post(f"{IRIS_URL}/cortex-module/executions/{final['id']}/operations/{ops['AddTagToArtifact']['index']}/apply",
              json={}))
    ok(s.post(f"{IRIS_URL}/cortex-module/executions/{final['id']}/operations/{ops['CreateTask']['index']}/apply",
              json={}))
    again = s.post(f"{IRIS_URL}/cortex-module/executions/{final['id']}/operations/{ops['CreateTask']['index']}/apply",
                   json={})
    assert again.status_code == 409
    ioc = ok(s.get(f"{IRIS_URL}/case/ioc/{iris['ip']}", params={"cid": CASE_ID}))
    assert "PaloAltoNGFW_block_ip_1_0:done" in ioc["ioc_tags"]
    tasks = ok(s.get(f"{IRIS_URL}/case/tasks/list", params={"cid": CASE_ID}))["tasks"]
    assert any(t["task_title"] == "Validar bloqueio" for t in tasks)
    timeline = ok(s.get(f"{IRIS_URL}/case/timeline/events/list", params={"cid": CASE_ID}))["timeline"]
    assert any(e["event_title"].startswith("Cortex Responder executed: PaloAltoNGFW_block_ip_1_0") for e in timeline)


def test_case_level_responder_gets_thehive_case(iris):
    s = iris["s"]
    execution = ok(s.post(f"{IRIS_URL}/cortex-module/responders/run", json={
        "kind": "case", "object_id": CASE_ID, "context_type": "case", "context_id": CASE_ID,
        "responder_id": "mailer", "confirm": True, "request_uuid": str(uuid.uuid4())}))
    sent = [json.loads(r["body"]) for r in mock_requests() if r["path"].startswith("/api/responder/mailer/run")][-1]
    assert sent["dataType"] == "thehive:case" and sent["data"]["_type"] == "case"
    assert sent["data"]["caseId"] == CASE_ID and isinstance(sent["data"]["artifacts"], list)
    assert wait_final(s, execution["id"])["status"] == "success"


@pytest.mark.skipif(not ALERT_ID, reason="IRIS_ALERT_ID not set")
def test_alert_context(iris):
    s = iris["s"]
    alert_id = int(ALERT_ID)
    data = ok(catalog(s, "alert", alert_id, ctype="alert", cid=alert_id))
    assert data["object"]["responder_data_type"] == "thehive:alert"
    ioc = data["context_objects"]["ioc"][0]
    execution = ok(run(s, "ioc", ioc["id"], ["vt"], ctype="alert", cid=alert_id))[0]
    assert wait_final(s, execution["id"])["status"] == "success"
    alert = ok(s.get(f"{IRIS_URL}/alerts/{alert_id}"))
    assert any("Cortex analyzer VirusTotal_GetReport_3_1" in (h.get("action") or "")
               for h in (alert.get("modification_history") or {}).values())


def test_history_and_admin_logs(iris):
    s = iris["s"]
    history = ok(s.get(f"{IRIS_URL}/cortex-module/history/case/{CASE_ID}"))
    assert {"analyzer", "responder"} <= {h["worker_type"] for h in history}
    logs = ok(s.get(f"{IRIS_URL}/cortex-module/logs", params={"worker_type": "responder"}))
    item = logs["items"][0]
    assert item["request_payload"]["dataType"].startswith("thehive:") and item["client_ip"]


def test_rbac_standard_analyst(iris):
    s = iris["s"]
    login = f"analyst_{iris['suffix']}"
    user = ok(s.post(f"{IRIS_URL}/manage/users/add", json={
        "user_login": login, "user_name": "Analyst IT", "user_email": f"{login}@example.com",
        "user_password": "Very-Str0ng-Passw0rd!", "user_is_service_account": False}))
    groups = {g["group_name"]: g["group_id"] for g in ok(s.get(f"{IRIS_URL}/manage/groups/list"))}
    ok(s.post(f"{IRIS_URL}/manage/users/{user['id']}/groups/update", json={"groups_membership": [groups["Analysts"]]}))
    ok(s.post(f"{IRIS_URL}/manage/users/{user['id']}/cases-access/update", json={"cases_list": [CASE_ID],
                                                                                  "access_level": 4}))
    analyst = session(user["user_api_key"])

    # Defaults: analyzers allowed, responders deny-by-default.
    data = ok(catalog(analyst, "ioc", iris["ip"]))
    assert "cortex.analyzer.execute" in data["roles"] and "cortex.responder.execute" not in data["roles"]
    assert data["responders"] and not any(r["allowed"] for r in data["responders"])
    body = {"kind": "ioc", "object_id": iris["ip"], "context_type": "case", "context_id": CASE_ID,
            "responder_id": "misp_export", "confirm": True, "request_uuid": str(uuid.uuid4())}
    r = analyst.post(f"{IRIS_URL}/cortex-module/responders/run", json=body)
    assert r.status_code == 403 and "responders" in js(r)["message"]
    assert analyst.get(f"{IRIS_URL}/cortex-module/logs").status_code == 403

    # Group grants standard responders, but not privileged ones.
    set_params(iris, groups_responder="Analysts")
    assert analyst.post(f"{IRIS_URL}/cortex-module/responders/run",
                        json={**body, "request_uuid": str(uuid.uuid4())}).status_code == 200
    r = analyst.post(f"{IRIS_URL}/cortex-module/responders/run",
                     json={**body, "responder_id": "block", "request_uuid": str(uuid.uuid4())})
    assert r.status_code == 403 and "contenção" in js(r)["message"]

    # Analyzer group restriction.
    set_params(iris, groups_responder="", groups_analyzer="nobody-group")
    r = run(analyst, "ioc", iris["ip"], ["abuseipdb"])
    assert r.status_code == 403
    set_params(iris, groups_analyzer="")


def test_customer_specific_organisation(iris):
    customer = ok(iris["s"].get(f"{IRIS_URL}/cortex-module/observables/case/{CASE_ID}",
                                params={"context_type": "case", "context_id": CASE_ID}))["object"]["customer"]
    set_params(iris, customer_api_keys=json.dumps({customer: "ACME_CORTEX_KEY"}))
    try:
        execution = ok(run(iris["s"], "ioc", iris["ip"], ["shodan"]))[0]
        final = wait_final(iris["s"], execution["id"])
        assert final["status"] == "success"
        # The mock scopes jobs per organisation: success proves the ACME key was used end to end.
        set_params(iris, customer_api_keys=json.dumps({customer: "UNDEFINED_CORTEX_KEY"}))
        r = run(iris["s"], "ioc", iris["ip"], ["shodan"])
        assert r.status_code == 503 and "UNDEFINED_CORTEX_KEY" in js(r)["message"]
    finally:
        set_params(iris, customer_api_keys="{}")


def test_cortex_unavailable_is_reported(iris):
    set_params(iris, cortex_url="http://mock-cortex:9")
    try:
        data = ok(catalog(iris["s"], "ioc", iris["ip"]))
        assert data["cortex_error"] and "indisponível" in data["cortex_error"]
        assert data["history"]                                   # history still available
        r = run(iris["s"], "ioc", iris["ip"], ["abuseipdb"])
        assert r.status_code == 503
    finally:
        set_params(iris, cortex_url=MOCK_FROM_IRIS)


def test_api_key_typed_as_env_name_is_refused_without_echo(iris):
    set_params(iris, cortex_api_key_env="s3cr3t-Key!")
    try:
        r = iris["s"].get(f"{IRIS_URL}/cortex-module/status")
        assert r.status_code == 503 and "s3cr3t" not in r.text and "NAME" in js(r)["message"]
    finally:
        set_params(iris, cortex_api_key_env=MOCK_KEY_ENV)
