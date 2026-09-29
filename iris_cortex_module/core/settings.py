"""Module settings.

Priority, highest first: environment ``IRIS_CORTEX_<PARAM_NAME_UPPER>``, the module configuration
edited in Advanced > Modules, then the defaults below.

The Cortex API key is never a module parameter (IRIS stores module parameters in clear text and
exports them). ``cortex_api_key_env`` holds the NAME of the environment variable; ``<NAME>_FILE``
is read too (Docker/Kubernetes secrets). ``customer_api_keys`` maps IRIS customers to other
variable names, for multi-tenant Cortex setups (one Cortex organisation per customer).
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

ENV_PREFIX = "IRIS_CORTEX_"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

DEFAULT_PRIVILEGED_RESPONDERS = ("*block*", "*isolat*", "*quarantin*", "*contain*", "*disable*",
                                 "*delete*", "*kill*", "*ban*", "*revoke*", "*reset*")


class ConfigError(ValueError):
    """Raised when the module configuration is unusable. Messages never include secret values."""


def _param(name, human, description, default, ptype="string", mandatory=False):
    return {"param_name": name, "param_human_name": human, "param_description": description,
            "default": default, "mandatory": mandatory, "type": ptype}


PARAMETERS: List[Dict[str, Any]] = [
    # Connection
    _param("cortex_url", "Cortex URL", "Base URL of Cortex, e.g. https://cortex.example.com:9001", "", "string", True),
    _param("cortex_api_key_env", "API key env var",
           "NAME of the environment variable holding the Cortex API key -- NOT the key itself. "
           "<NAME>_FILE is also read. Use a Cortex user with the 'analyze' role only (never orgAdmin).",
           "IRIS_CORTEX_API_KEY", "string", True),
    _param("customer_api_keys", "API key per IRIS customer",
           "Optional JSON object {\"IRIS customer name\": \"ENV_VAR_NAME\"} to use a different Cortex "
           "organisation per customer. Customers not listed use the default key.", "{}", "textfield_json", False),
    _param("verify_tls", "Verify TLS certificate", "Verify the Cortex certificate and hostname", True, "bool", True),
    _param("ca_file", "CA bundle", "Optional CA bundle path used to verify Cortex", "", "string", False),
    _param("timeout", "HTTP timeout (s)", "Timeout of each HTTP request to Cortex", 30, "int", True),
    _param("max_retries", "Max retries", "Retries for read requests (GET/status) on network errors, 429 and 5xx. "
           "Job creation is never retried automatically.", 3, "int", True),
    _param("poll_interval", "Job polling interval (s)", "Delay between job status checks", 10, "int", True),
    _param("job_timeout", "Job timeout (s)", "An execution still running after this delay is marked as timeout",
           900, "int", True),
    # Scope
    _param("enable_for_iocs", "Enable for IOCs", "", True, "bool", True),
    _param("enable_for_evidences", "Enable for evidences", "Evidences are analysed by hash and file name",
           True, "bool", True),
    _param("enable_for_files", "Enable for datastore files", "Upload case datastore files to file analyzers",
           True, "bool", True),
    _param("enable_for_cases", "Enable for cases", "Case-level responders (thehive:case)", True, "bool", True),
    _param("enable_for_alerts", "Enable for alerts", "Alert-level responders (thehive:alert)", True, "bool", True),
    _param("datatype_mapping", "IRIS -> Cortex data types",
           "Optional JSON object overriding the built-in mapping, e.g. {\"ip-dst\": \"ip\", \"mutex\": \"other\"}",
           "{}", "textfield_json", False),
    _param("analyzer_allowlist", "Analyzer allow-list",
           "Comma-separated name patterns (fnmatch, case-insensitive). Empty = all enabled analyzers.", "",
           "string", False),
    _param("analyzer_denylist", "Analyzer deny-list", "Comma-separated name patterns never offered", "",
           "string", False),
    _param("responder_allowlist", "Responder allow-list", "Comma-separated name patterns. Empty = all.", "",
           "string", False),
    # Classification policy
    _param("max_tlp", "Max TLP sent to Cortex",
           "Observables above this TLP are never sent: clear, green, amber, amber+strict or red", "amber",
           "string", True),
    _param("max_pap", "Max PAP sent to Cortex", "clear, green, amber or red", "amber", "string", True),
    _param("default_pap", "Default PAP", "PAP attached to observables (IRIS has no PAP field)", "amber",
           "string", True),
    # RBAC (IRIS group names)
    _param("groups_view", "Groups: cortex.view", "Comma-separated IRIS groups. Empty = any user with access "
           "to the object.", "", "string", False),
    _param("groups_analyzer", "Groups: cortex.analyzer.execute", "Empty = any user with write access to the object",
           "", "string", False),
    _param("groups_responder", "Groups: cortex.responder.execute",
           "Empty = nobody except cortex.admin (responders are deny-by-default)", "", "string", False),
    _param("groups_responder_privileged", "Groups: cortex.responder.privileged",
           "Required for responders matching privileged_responders. Empty = nobody except cortex.admin", "",
           "string", False),
    _param("groups_admin", "Groups: cortex.admin", "IRIS server administrators are always cortex.admin", "",
           "string", False),
    _param("privileged_responders", "Privileged responders",
           "Comma-separated name patterns of containment/destructive responders",
           ",".join(DEFAULT_PRIVILEGED_RESPONDERS), "string", False),
    # Limits
    _param("max_analyzers_per_request", "Max analyzers per request", "", 10, "int", True),
    _param("rate_limit_analyzer_user_hour", "Analyzer runs / user / hour", "0 disables", 100, "int", True),
    _param("rate_limit_responder_user_hour", "Responder runs / user / hour", "0 disables", 20, "int", True),
    _param("max_observable_length", "Max observable length", "Characters", 8192, "int", True),
    _param("max_file_size_mb", "Max file size (MB)", "Datastore files sent to file analyzers", 25, "int", True),
    _param("max_report_kb", "Max stored report (KB)", "Larger full reports are stored truncated", 2048, "int", True),
    _param("max_artifacts_import", "Max artifacts imported at once", "", 50, "int", True),
    # Behaviour
    _param("force_run", "Bypass Cortex job cache", "Send force=1 so Cortex never returns a cached job",
           False, "bool", True),
    _param("write_ioc_tab", "Write 'Cortex' tab on IOCs",
           "Keep a sanitised summary of the latest results in a Cortex tab of the IOC", True, "bool", True),
    _param("add_timeline_event", "Add case timeline events", "Alerts always get a history entry", True, "bool", True),
]

_TYPES = {p["param_name"]: p["type"] for p in PARAMETERS}
_DEFAULTS = {p["param_name"]: p["default"] for p in PARAMETERS}

TLP_LEVELS = {"clear": 0, "white": 0, "green": 1, "amber": 2, "amber+strict": 3, "red": 3}
PAP_LEVELS = {"clear": 0, "white": 0, "green": 1, "amber": 2, "red": 3}


def _split_csv(value: Any) -> Tuple[str, ...]:
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple)) else str(value).replace(";", ",").split(",")
    return tuple(str(i).strip().lower() for i in items if str(i).strip())


def _cast(name: str, value: Any) -> Any:
    ptype = _TYPES.get(name, "string")
    if value is None:
        return None
    if ptype == "bool":
        return value if isinstance(value, bool) else str(value).strip().lower() in ("1", "true", "yes", "on")
    if ptype == "int":
        try:
            return int(str(value).strip())
        except ValueError:
            raise ConfigError(f"Parameter {name} must be an integer")
    if ptype == "textfield_json":
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value) if str(value).strip() else {}
        except json.JSONDecodeError as e:
            raise ConfigError(f"Parameter {name} is not valid JSON: {e.msg} (line {e.lineno})")
    return str(value).strip()


def merge_sources(module_params: Optional[Mapping[str, Any]],
                  environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    environ = os.environ if environ is None else environ
    merged: Dict[str, Any] = {}
    for name, default in _DEFAULTS.items():
        value = default
        if module_params and module_params.get(name) not in (None, ""):
            value = module_params[name]
        env_value = environ.get(ENV_PREFIX + name.upper())
        if env_value not in (None, ""):
            value = env_value
        merged[name] = _cast(name, value)
    return merged


def matches_any(name: str, patterns: Tuple[str, ...]) -> bool:
    lowered = (name or "").lower()
    return any(fnmatch.fnmatchcase(lowered, p) for p in patterns)


def _level(value: str, table: Mapping[str, int], param: str) -> int:
    key = (value or "").strip().lower()
    if key not in table:
        raise ConfigError(f"{param} must be one of {', '.join(sorted(set(table)))}")
    return table[key]


@dataclass(frozen=True)
class CortexSettings:
    cortex_url: str = ""
    cortex_api_key_env: str = "IRIS_CORTEX_API_KEY"
    customer_api_keys: Mapping[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    ca_file: str = ""
    timeout: int = 30
    max_retries: int = 3
    poll_interval: int = 10
    job_timeout: int = 900
    enable_for_iocs: bool = True
    enable_for_evidences: bool = True
    enable_for_files: bool = True
    enable_for_cases: bool = True
    enable_for_alerts: bool = True
    datatype_mapping: Mapping[str, str] = field(default_factory=dict)
    analyzer_allowlist: Tuple[str, ...] = ()
    analyzer_denylist: Tuple[str, ...] = ()
    responder_allowlist: Tuple[str, ...] = ()
    max_tlp: int = 2
    max_pap: int = 2
    default_pap: int = 2
    groups_view: Tuple[str, ...] = ()
    groups_analyzer: Tuple[str, ...] = ()
    groups_responder: Tuple[str, ...] = ()
    groups_responder_privileged: Tuple[str, ...] = ()
    groups_admin: Tuple[str, ...] = ()
    privileged_responders: Tuple[str, ...] = DEFAULT_PRIVILEGED_RESPONDERS
    max_analyzers_per_request: int = 10
    rate_limit_analyzer_user_hour: int = 100
    rate_limit_responder_user_hour: int = 20
    max_observable_length: int = 8192
    max_file_size_mb: int = 25
    max_report_kb: int = 2048
    max_artifacts_import: int = 50
    force_run: bool = False
    write_ioc_tab: bool = True
    add_timeline_event: bool = True
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ, repr=False, compare=False)

    @classmethod
    def from_sources(cls, module_params: Optional[Mapping[str, Any]] = None,
                     environ: Optional[Mapping[str, str]] = None) -> "CortexSettings":
        environ = os.environ if environ is None else environ
        m = merge_sources(module_params, environ)
        customer_keys = m["customer_api_keys"] or {}
        mapping = m["datatype_mapping"] or {}
        if not isinstance(customer_keys, dict):
            raise ConfigError("customer_api_keys must be a JSON object")
        if not isinstance(mapping, dict):
            raise ConfigError("datatype_mapping must be a JSON object")
        settings = cls(
            cortex_url=(m["cortex_url"] or "").rstrip("/"),
            cortex_api_key_env=m["cortex_api_key_env"] or "",
            customer_api_keys={str(k).strip().lower(): str(v).strip() for k, v in customer_keys.items()},
            verify_tls=m["verify_tls"],
            ca_file=m["ca_file"] or "",
            timeout=m["timeout"],
            max_retries=m["max_retries"],
            poll_interval=m["poll_interval"],
            job_timeout=m["job_timeout"],
            enable_for_iocs=m["enable_for_iocs"],
            enable_for_evidences=m["enable_for_evidences"],
            enable_for_files=m["enable_for_files"],
            enable_for_cases=m["enable_for_cases"],
            enable_for_alerts=m["enable_for_alerts"],
            datatype_mapping={str(k).strip().lower(): str(v).strip().lower() for k, v in mapping.items()},
            analyzer_allowlist=_split_csv(m["analyzer_allowlist"]),
            analyzer_denylist=_split_csv(m["analyzer_denylist"]),
            responder_allowlist=_split_csv(m["responder_allowlist"]),
            max_tlp=_level(m["max_tlp"], TLP_LEVELS, "max_tlp"),
            max_pap=_level(m["max_pap"], PAP_LEVELS, "max_pap"),
            default_pap=_level(m["default_pap"], PAP_LEVELS, "default_pap"),
            groups_view=_split_csv(m["groups_view"]),
            groups_analyzer=_split_csv(m["groups_analyzer"]),
            groups_responder=_split_csv(m["groups_responder"]),
            groups_responder_privileged=_split_csv(m["groups_responder_privileged"]),
            groups_admin=_split_csv(m["groups_admin"]),
            privileged_responders=_split_csv(m["privileged_responders"]),
            max_analyzers_per_request=m["max_analyzers_per_request"],
            rate_limit_analyzer_user_hour=m["rate_limit_analyzer_user_hour"],
            rate_limit_responder_user_hour=m["rate_limit_responder_user_hour"],
            max_observable_length=m["max_observable_length"],
            max_file_size_mb=m["max_file_size_mb"],
            max_report_kb=m["max_report_kb"],
            max_artifacts_import=m["max_artifacts_import"],
            force_run=m["force_run"],
            write_ioc_tab=m["write_ioc_tab"],
            add_timeline_event=m["add_timeline_event"],
            environ=environ,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.cortex_url:
            raise ConfigError("cortex_url is required")
        if not self.cortex_url.startswith(("https://", "http://")):
            raise ConfigError("cortex_url must start with https:// or http://")
        names = [("cortex_api_key_env", self.cortex_api_key_env)] + \
                [(f"customer_api_keys[{k}]", v) for k, v in self.customer_api_keys.items()]
        for param, name in names:
            if not name or not _ENV_NAME_RE.match(name):
                # Never echo the value: it is most likely the key itself.
                raise ConfigError(f"{param} must be the NAME of an environment variable (e.g. IRIS_CORTEX_API_KEY), "
                                  "not the API key. Put the key in that variable (.env / secret) and restart "
                                  "the app and worker containers.")
        for name, low, high in (("timeout", 1, 300), ("max_retries", 0, 10), ("poll_interval", 2, 600),
                                ("job_timeout", 30, 86400), ("max_analyzers_per_request", 1, 50),
                                ("max_observable_length", 1, 1_000_000), ("max_file_size_mb", 1, 2048),
                                ("max_report_kb", 16, 65536), ("max_artifacts_import", 1, 1000)):
            value = getattr(self, name)
            if not low <= value <= high:
                raise ConfigError(f"{name} must be between {low} and {high}")
        for name in ("rate_limit_analyzer_user_hour", "rate_limit_responder_user_hour"):
            if getattr(self, name) < 0:
                raise ConfigError(f"{name} must be >= 0")
        if self.default_pap > self.max_pap:
            raise ConfigError("default_pap cannot be higher than max_pap")

    def api_key_env_for(self, customer_name: Optional[str]) -> str:
        if customer_name and customer_name.strip().lower() in self.customer_api_keys:
            return self.customer_api_keys[customer_name.strip().lower()]
        return self.cortex_api_key_env

    def api_key(self, customer_name: Optional[str] = None) -> Optional[str]:
        """Read the API key at use time. Never cached, never logged."""
        env_name = self.api_key_env_for(customer_name)
        value = self.environ.get(env_name)
        if value:
            return value.strip()
        path = self.environ.get(env_name + "_FILE")
        if path:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return fh.read().strip()
            except OSError as e:
                raise ConfigError(f"Unable to read the Cortex API key file from {env_name}_FILE: {e.strerror}")
        return None

    def analyzer_offered(self, name: str) -> bool:
        if self.analyzer_denylist and matches_any(name, self.analyzer_denylist):
            return False
        return not self.analyzer_allowlist or matches_any(name, self.analyzer_allowlist)

    def responder_offered(self, name: str) -> bool:
        return not self.responder_allowlist or matches_any(name, self.responder_allowlist)

    def is_privileged_responder(self, name: str) -> bool:
        return matches_any(name, self.privileged_responders)
