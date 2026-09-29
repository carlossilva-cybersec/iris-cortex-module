import json

from iris_cortex_module.core.observables import artifact_entity, case_entity, severity_to_thehive
from iris_cortex_module.core.results import (
    bounded_json, parse_report, render_ioc_tab_html, sanitize_json,
)
from tests.mock_cortex.server import ANALYZERS, RESPONDERS, _report_for


def test_parse_success_report():
    parsed = parse_report(_report_for(ANALYZERS[0], "ip", "185.220.101.10"))
    assert parsed.success and parsed.verdict == "malicious"
    assert parsed.taxonomies[0] == {"level": "malicious", "namespace": "VirusTotal", "predicate": "Score",
                                    "value": "12/70"}
    assert ("country", "DE") in parsed.highlights
    importable = [a for a in parsed.artifacts if a.importable]
    assert [(a.iris_type, a.data) for a in importable] == [
        ("domain", "evil.example"), ("ip-any", "203.0.113.7"), ("md5", "44d88612fea8a8f36de82e1278abb02f")]
    bogus = [a for a in parsed.artifacts if not a.importable]
    assert bogus and "javascript" in bogus[0].data
    assert sum(1 for a in parsed.artifacts if a.data == "evil.example") == 1     # deduplicated


def test_parse_failure_report():
    parsed = parse_report({"errorMessage": "Invalid API key", "input": None, "success": False})
    assert not parsed.success and parsed.error_message == "Invalid API key"
    assert not parse_report("Running").success


def test_unknown_taxonomy_level_becomes_info():
    parsed = parse_report({"success": True, "summary": {"taxonomies": [{"level": "<b>evil</b>", "namespace": "x",
                                                                        "predicate": "y", "value": "z"}]}})
    assert parsed.taxonomies[0]["level"] == "info"


def test_responder_operations():
    parsed = parse_report(_report_for(RESPONDERS[1], "thehive:case_artifact", None))
    assert [(o["type"], o["supported"]) for o in parsed.operations] == [("AddTagToArtifact", True),
                                                                          ("CreateTask", True)]
    unsupported = parse_report({"success": True, "operations": [{"type": "AddCustomFields", "name": "x"},
                                                                {"type": "AddTagToCase", "tag": ""}]})
    assert [o["supported"] for o in unsupported.operations] == [False, False]


def test_sanitize_limits():
    deep = {}
    node = deep
    for _ in range(50):
        node["x"] = {}
        node = node["x"]
    assert "depth limit" in json.dumps(sanitize_json(deep))
    assert len(sanitize_json(list(range(5000)))) == 1001
    assert sanitize_json("a\x00b\x07c") == "abc"
    assert sanitize_json(float("nan")) == "nan"
    value, truncated = bounded_json({"k": "x" * 5000}, 1000)
    assert truncated and value["_truncated"]


def test_ioc_tab_html_is_escaped():
    out = render_ioc_tab_html([{"worker_name": "<script>x</script>", "status": "Success", "verdict": "malicious",
                                "finished_at": "2026-09-29T10:34:22", "user_login": "a\"b",
                                "taxonomies": [{"level": "malicious", "namespace": "<img src=x onerror=1>",
                                                "predicate": "p", "value": "v"}]}])
    assert "<script>" not in out and "<img" not in out and "&lt;script&gt;" in out


def test_thehive_entities():
    art = artifact_entity(ioc_id=5, value="1.2.3.4", data_type="ip", tlp=2, pap=2, tags=["t"], message="m",
                          case_id=9)
    assert art["_type"] == "case_artifact" and art["_id"] == "iris-ioc-5" and art["case"]["caseId"] == 9
    case = case_entity(case_id=9, title="Ransomware", description="d", severity=severity_to_thehive("High"),
                       tlp=2, pap=2, tags=[], owner="ana", status="Open", customer="ACME")
    assert case["_type"] == "case" and case["severity"] == 3 and case["caseId"] == 9
