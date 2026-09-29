"""IRIS (MISP taxonomy) <-> Cortex data types, value validation and TLP conversion."""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Mapping, Optional, Tuple

# Data types understood by the Cortex-Analyzers ecosystem.
CORTEX_DATATYPES = (
    "autonomous-system", "domain", "file", "filename", "fqdn", "hash", "ip", "mail", "mail_subject",
    "other", "registry", "regexp", "uri_path", "url", "user-agent",
)

# IRIS type -> Cortex data type for simple (non composite) types.
_SIMPLE: Dict[str, str] = {
    "ip-any": "ip", "ip-dst": "ip", "ip-src": "ip",
    "domain": "domain",
    "hostname": "fqdn",
    "url": "url", "link": "url",
    "uri": "uri_path",
    "md5": "hash", "sha1": "hash", "sha224": "hash", "sha256": "hash", "sha384": "hash", "sha512": "hash",
    "sha512/224": "hash", "sha512/256": "hash", "sha3-224": "hash", "sha3-256": "hash", "sha3-384": "hash",
    "sha3-512": "hash",
    "email": "mail", "email-src": "mail", "email-dst": "mail", "email-reply-to": "mail", "target-email": "mail",
    "whois-registrant-email": "mail", "dns-soa-email": "mail",
    "email-subject": "mail_subject",
    "filename": "filename", "email-attachment": "filename",
    "user-agent": "user-agent",
    "AS": "autonomous-system",
    "regkey": "registry",
}

# Composite IRIS types: "left|right" values, each part mapped separately.
_COMPOSITE: Dict[str, Tuple[str, str]] = {
    "domain|ip": ("domain", "ip"),
    "ip-dst|port": ("ip", ""),
    "ip-src|port": ("ip", ""),
    "hostname|port": ("fqdn", ""),
    "regkey|value": ("registry", ""),
}
for _h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256",
           "sha3-224", "sha3-256", "sha3-384", "sha3-512"):
    _COMPOSITE[f"filename|{_h}"] = ("filename", "hash")

# Cortex data type -> IRIS type used when importing report artifacts as new IOCs.
CORTEX_TO_IRIS: Dict[str, str] = {
    "ip": "ip-any", "domain": "domain", "fqdn": "hostname", "url": "url", "uri_path": "uri",
    "mail": "email", "mail_subject": "email-subject", "filename": "filename", "user-agent": "user-agent",
    "autonomous-system": "AS", "registry": "regkey", "other": "other",
}
_HASH_BY_LENGTH = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}

# IRIS TLP names -> Cortex numeric TLP. amber+strict has no Cortex equivalent: mapped to the
# stricter level so that it is never sent where only AMBER is allowed.
IRIS_TLP_TO_CORTEX = {"clear": 0, "white": 0, "green": 1, "amber": 2, "amber+strict": 3, "red": 3}
CORTEX_TLP_NAMES = {0: "CLEAR", 1: "GREEN", 2: "AMBER", 3: "RED"}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_MAIL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9.-]{1,253}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ObservableError(ValueError):
    """The value cannot be sent to Cortex as the requested data type."""


def cortex_candidates(iris_type: str, value: str,
                      overrides: Optional[Mapping[str, str]] = None) -> List[Tuple[str, str]]:
    """Return [(cortex_data_type, value)] for an IRIS IOC. Composite types yield up to two entries."""
    overrides = overrides or {}
    key = (iris_type or "").strip()
    override = overrides.get(key.lower())
    if override:
        return [(override, value)]
    if key in _COMPOSITE and "|" in (value or ""):
        left_type, right_type = _COMPOSITE[key]
        left, right = value.split("|", 1)
        result = [(left_type, left.strip())]
        if right_type:
            result.append((right_type, right.strip()))
        return [(t, v) for t, v in result if v]
    if key in _SIMPLE:
        return [(_SIMPLE[key], value)]
    return [("other", value)]


def hash_kind(value: str) -> Optional[str]:
    value = (value or "").strip()
    if _HEX_RE.match(value):
        return _HASH_BY_LENGTH.get(len(value))
    return None


def _valid_hostname(value: str) -> bool:
    try:
        ascii_value = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_value.split(".")
    return len(ascii_value) <= 253 and len(labels) >= 2 and all(_LABEL_RE.match(label) for label in labels)


def normalize_value(data_type: str, value: str, max_length: int = 8192) -> str:
    """Validate an observable before it leaves IRIS. Raises ObservableError."""
    if not isinstance(value, str):
        raise ObservableError("Observable value must be text")
    value = value.strip()
    if not value:
        raise ObservableError("Observable value is empty")
    if len(value) > max_length:
        raise ObservableError(f"Observable longer than {max_length} characters")
    if _CONTROL_RE.search(value):
        raise ObservableError("Observable contains control characters")

    if data_type == "ip":
        candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
        try:
            return str(ipaddress.ip_address(candidate.split("%")[0]))
        except ValueError:
            try:
                return str(ipaddress.ip_network(candidate, strict=False))
            except ValueError:
                raise ObservableError(f"'{value}' is not a valid IP address")
    if data_type in ("domain", "fqdn"):
        if not _valid_hostname(value):
            raise ObservableError(f"'{value}' is not a valid {data_type}")
        return value.rstrip(".").lower()
    if data_type == "url":
        if not re.match(r"(?i)^(https?|ftp)://[^\s]+$", value):
            raise ObservableError(f"'{value}' is not a valid URL (http, https or ftp)")
        return value
    if data_type == "hash":
        if not hash_kind(value):
            raise ObservableError(f"'{value}' is not a MD5/SHA1/SHA224/SHA256/SHA384/SHA512 hash")
        return value.lower()
    if data_type == "mail":
        if not _MAIL_RE.match(value) or not _valid_hostname(value.rsplit("@", 1)[1]):
            raise ObservableError(f"'{value}' is not a valid e-mail address")
        return value
    if data_type == "autonomous-system":
        digits = re.sub(r"(?i)^AS", "", value)
        if not digits.isdigit() or not 0 < int(digits) < 4294967296:
            raise ObservableError(f"'{value}' is not a valid AS number")
        return digits
    if data_type == "file":
        raise ObservableError("Files are sent as attachments, not as values")
    return value


def iris_type_for_artifact(cortex_type: str, value: str) -> Optional[str]:
    """IRIS IOC type for a Cortex report artifact, or None when it cannot be imported."""
    cortex_type = (cortex_type or "").strip().lower()
    if cortex_type == "hash":
        return hash_kind(value)
    if cortex_type == "file":
        return None     # attachments are not imported as IOCs
    return CORTEX_TO_IRIS.get(cortex_type)


def iris_tlp_to_cortex(tlp_name: Optional[str]) -> int:
    """Unknown or missing TLP is treated as AMBER, like Cortex's own default."""
    return IRIS_TLP_TO_CORTEX.get((tlp_name or "").strip().lower(), 2)
