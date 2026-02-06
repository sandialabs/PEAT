import ipaddress
import re
from pathlib import Path, PurePath

from pydantic.fields import ModelField

from peat.protocols.addresses import clean_ipv4, clean_mac

MAC_REGEX_UPPER = re.compile(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", flags=re.ASCII)

# NOTE: last updated for ECS 8.1.0 on April 28 2022
# Fields: category, kind, outcome, type
ECS_EVENT_VALUES: dict[str, set[str]] = {
    # https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html
    "category": {
        "api",  # Added in ECS 8.7.0
        "authentication",
        "configuration",
        "database",
        "driver",
        "email",
        "file",
        "host",
        "iam",
        "intrusion_detection",
        "library",  # Added in ECS 8.7.0
        "malware",
        "network",
        "package",
        "process",
        "registry",
        "session",
        "threat",
        "vulnerability",  # Added in ECS 8.6.0
        "web",
    },
    # https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html
    "kind": {
        "alert",
        "asset",  # Added in ECS 8.8.0
        "enrichment",
        "event",
        "metric",
        "state",
        "pipeline_error",
        "signal",
    },
    # https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html
    "outcome": {
        "failure",
        "success",
        "unknown",
    },
    # https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html
    "type": {
        "access",
        "admin",
        "allowed",
        "change",
        "connection",
        "creation",
        "deletion",
        "denied",
        "end",
        "error",
        "group",
        "indicator",
        "info",
        "installation",
        "protocol",
        "start",
        "user",
    },
}


def validate_ecs(v: str, field: ModelField) -> str:
    """Elastic Common Schema (ECS) fields: category, kind, outcome, type."""
    if not v:
        return v

    v = v.strip().lower().replace(" ", "_").replace("-", "_")

    # for some reason a "_" gets prepended
    # e.g. "category" gets changed to "_category"
    field_name = field.name.replace("_", "")

    if v not in ECS_EVENT_VALUES[field_name]:
        raise ValueError(
            f"{v} is an invalid ECS Event value for {field_name}, "
            f"expected one of {ECS_EVENT_VALUES[field_name]}"
        )

    return v


def validate_ip(v: str) -> str:
    if not v:
        return ""

    v = v.strip().replace(" ", "")
    if "." in v:
        v = clean_ipv4(v)  # strip leading zeros

    # NOTE: this will raise ValueError if not valid IPv4 or IPv6 address
    return str(ipaddress.ip_address(v))


def validate_mac(v: str) -> str:
    if not v:
        return ""

    # cleans and converts to uppercase colon-separated
    v = clean_mac(v)

    if len(v) != 17 or ":" not in v or not MAC_REGEX_UPPER.fullmatch(v):
        raise ValueError(f"invalid MAC address {v}")

    return v


def validate_hash(v: str) -> str:
    if not v:
        return ""

    v = validate_hex(v)

    # MD5, SHA1, SHA256, SHA512
    valid_lengths = {32, 40, 64, 128}
    if len(v) not in valid_lengths:
        raise ValueError(f"invalid length {len(v)} for hash '{v}', must be one of {valid_lengths}")

    return v


def validate_hex(v: str) -> str:
    if not v:
        return ""

    v = str(v).replace("0x", "").replace("0X", "").replace(" ", "").strip().upper()

    try:
        int(v, 16)
    except Exception:
        raise ValueError(f"invalid hexadecimal string '{v}'") from None

    return v


def cleanstr(v: str) -> str:
    if not v:
        return ""

    if not isinstance(v, str):
        raise TypeError("type must be str")

    return v.strip().lower().replace(" ", "_")


def clean_protocol(v: str) -> str:
    """Replace spaces and dashes with underscores."""
    return v.replace("-", "_")


def strip_quotes(v: str) -> str:
    """Remove trailing " and ' characters."""
    if not v:
        return ""

    return str(v).strip().strip('"').strip().strip("'").strip()


def convert_arbitrary_path_to_purepath(v) -> PurePath:
    if isinstance(v, PurePath):
        return v
    if isinstance(v, bytes):
        v = v.decode()
    if isinstance(v, (Path, str)):
        return PurePath(v)
    raise ValueError(f"invalid file path: {v}")
