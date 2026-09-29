import json

import pytest

from iris_cortex_module.core.policy import (
    ROLE_ADMIN, ROLE_ANALYZER, ROLE_RESPONDER, ROLE_RESPONDER_PRIVILEGED, ROLE_VIEW, PolicyError, UserContext,
    check_classification, effective_roles, require, responder_role,
)
from iris_cortex_module.core.settings import PARAMETERS, ConfigError, CortexSettings

BASE = {"cortex_url": "https://cortex.local:9001"}


def s(**kw):
    return CortexSettings.from_sources({**BASE, **kw}, environ={})


def test_defaults():
    st = s()
    assert st.max_tlp == 2 and st.poll_interval == 10 and st.verify_tls
    assert not any(p["param_name"] in ("api_key", "cortex_api_key") for p in PARAMETERS)


def test_env_overrides():
    st = CortexSettings.from_sources(BASE, environ={"IRIS_CORTEX_MAX_TLP": "green", "IRIS_CORTEX_TIMEOUT": "5",
                                                     "IRIS_CORTEX_GROUPS_RESPONDER": "SOC N2, IR"})
    assert st.max_tlp == 1 and st.timeout == 5 and st.groups_responder == ("soc n2", "ir")


def test_api_key_from_env_file_and_customer(tmp_path):
    f = tmp_path / "k"
    f.write_text("from-file\n")
    env = {"IRIS_CORTEX_API_KEY": "default-key", "ACME_KEY_FILE": str(f)}
    st = CortexSettings.from_sources({**BASE, "customer_api_keys": json.dumps({"ACME Corp": "ACME_KEY"})}, environ=env)
    assert st.api_key(None) == "default-key"
    assert st.api_key("acme corp") == "from-file"
    assert st.api_key("Other") == "default-key"
    assert "default-key" not in repr(st)


@pytest.mark.parametrize("override", [
    {"cortex_url": ""}, {"cortex_url": "ftp://x"}, {"cortex_api_key_env": "sk-1234 5678!"},
    {"customer_api_keys": json.dumps({"ACME": "abc-def-123"})}, {"customer_api_keys": "[1]"},
    {"max_tlp": "purple"}, {"poll_interval": 1}, {"job_timeout": 5}, {"timeout": 0},
    {"max_analyzers_per_request": 0}, {"default_pap": "red", "max_pap": "amber"}, {"datatype_mapping": "{bad"},
])
def test_invalid(override):
    with pytest.raises(ConfigError):
        s(**override)


def test_key_typed_in_env_name_is_not_echoed():
    with pytest.raises(ConfigError) as exc:
        s(cortex_api_key_env="k3y-Secr3t!")
    assert "k3y-Secr3t" not in str(exc.value)


def test_allow_deny_and_privileged():
    st = s(analyzer_allowlist="virustotal*,abuseipdb*", analyzer_denylist="*_3_0")
    assert st.analyzer_offered("VirusTotal_GetReport_3_1")
    assert not st.analyzer_offered("VirusTotal_GetReport_3_0")
    assert not st.analyzer_offered("Shodan_Host_1_0")
    assert st.is_privileged_responder("PaloAltoNGFW_block_ip_1_0")
    assert st.is_privileged_responder("CrowdstrikeFalcon_Isolate_1_0")
    assert not st.is_privileged_responder("Mailer_1_0")


def user(groups=(), admin=False):
    return UserContext(1, "analyst01", frozenset(groups), admin)


def test_roles_defaults_are_deny_by_default_for_responders():
    roles = effective_roles(user(), s())
    assert roles == {ROLE_VIEW, ROLE_ANALYZER}
    with pytest.raises(PolicyError):
        require(roles, ROLE_RESPONDER)


def test_roles_by_group():
    st = s(groups_analyzer="tier1", groups_responder="tier2", groups_responder_privileged="ir", groups_view="all")
    assert effective_roles(user(["all"]), st) == {ROLE_VIEW}
    assert effective_roles(user(["tier1"]), st) == {ROLE_VIEW, ROLE_ANALYZER}
    assert ROLE_RESPONDER in effective_roles(user(["tier2"]), st)
    assert ROLE_RESPONDER_PRIVILEGED not in effective_roles(user(["tier2"]), st)
    assert ROLE_RESPONDER_PRIVILEGED in effective_roles(user(["ir"]), st)
    assert effective_roles(user(), st) == set()
    assert ROLE_ADMIN in effective_roles(user(admin=True), st)
    assert ROLE_ADMIN in effective_roles(user(["socadm"]), s(groups_admin="socadm"))


def test_responder_role_and_classification():
    st = s()
    assert responder_role(st, "PaloAltoNGFW_block_ip_1_0") == ROLE_RESPONDER_PRIVILEGED
    assert responder_role(st, "Mailer_1_0") == ROLE_RESPONDER
    check_classification(st, 2, 2)
    with pytest.raises(PolicyError) as exc:
        check_classification(st, 3, 2)
    assert "TLP:RED" in exc.value.message
