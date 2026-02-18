"""
Mappings (the Elastic "schema") for the various PEAT Elasticsearch indices.

These encode the types defined in the Elastic schemas for
integration of third-party tools and other Sandia capabilities.
Schema reference: :ref:`database-schema`

.. note::
   Type is only required for individual fields, NOT documents

Data structure

- Key: Name of the index (e.g. ``ot-device-hosts-timeseries``).
- Value: The field mapping for the index, including field types
    and other field configurations, such as tokenizers or filters.

Official Elasticsearch documentation and references

- `Mapping <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping.html>`__
- `Data types <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__
- `Nesting <https://www.elastic.co/guide/en/elasticsearch/reference/current/properties.html>`__
- `Create Index <https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-create-index.html>`__
- `Put Mapping <https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-put-mapping.html>`__

"""

from typing import Final

EsTypeType = dict[str, str | int]
MappingType = dict[str, EsTypeType]
NestedMappingType = dict[str, str | dict]

# -- Elasticsearch types --
BOOL: Final[EsTypeType] = {"type": "boolean"}
BINARY: Final[EsTypeType] = {"type": "binary"}
BYTE: Final[EsTypeType] = {"type": "byte"}
KEYWORD: Final[EsTypeType] = {"type": "keyword"}
IP: Final[EsTypeType] = {"type": "ip"}
# IP_RANGE: Final[EsTypeType] = {"type": "ip_range"}
INTEGER: Final[EsTypeType] = {"type": "integer"}
DATE: Final[EsTypeType] = {"type": "date"}
TEXT: Final[EsTypeType] = {"type": "text"}
LONG: Final[EsTypeType] = {"type": "long"}
DOUBLE: Final[EsTypeType] = {"type": "double"}
NESTED: Final[EsTypeType] = {"type": "nested"}

# NOTE: flattened is not "Final" due to a hack in elastic.py
FLATTENED: EsTypeType = {
    "type": "flattened",
    "ignore_above": 4096,
}

# *.field and *.field.text
KEYWORD_AND_TEXT: Final[NestedMappingType] = {
    "type": "keyword",
    "fields": {"text": TEXT},
}


# -- Reusable mapping definitions based on ECS --
VENDOR_FIELDS: Final[MappingType] = {
    "name": KEYWORD,
    "id": KEYWORD,
}

DESCRIPTION_FIELDS: Final[NestedMappingType] = {
    "brand": KEYWORD,
    "contact_info": KEYWORD_AND_TEXT,
    "description": KEYWORD_AND_TEXT,
    "full": KEYWORD_AND_TEXT,
    "model": KEYWORD,
    "product": KEYWORD_AND_TEXT,
    "vendor": {"properties": VENDOR_FIELDS},
}

HARDWARE_FIELDS: Final[NestedMappingType] = {
    "cpu": {"properties": DESCRIPTION_FIELDS},
    "id": KEYWORD,
    "storage_available": LONG,
    "storage_usage": LONG,
    "storage_total": LONG,
    "storage_type": KEYWORD,
    "memory_available": LONG,
    "memory_usage": LONG,
    "memory_total": LONG,
    "memory_type": KEYWORD,
    "revision": KEYWORD,
    "version": KEYWORD,
}

HASH_FIELDS: Final[MappingType] = {
    "md5": KEYWORD,
    "sha1": KEYWORD,
    "sha256": KEYWORD,
    "sha512": KEYWORD,
}

USER_FIELDS: Final[NestedMappingType] = {
    "description": KEYWORD_AND_TEXT,
    "domain": KEYWORD,
    "email": KEYWORD,
    "full_name": KEYWORD_AND_TEXT,
    "id": KEYWORD,
    "name": KEYWORD_AND_TEXT,
    "permissions": KEYWORD,
    "roles": KEYWORD,
    "uid": KEYWORD,
    "gid": KEYWORD,
    "extra": FLATTENED,
}

RELATED_FIELDS: Final[MappingType] = {
    "emails": KEYWORD,
    "files": KEYWORD,
    "hash": KEYWORD,
    "hosts": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "ports": LONG,
    "protocols": KEYWORD,
    "process": KEYWORD,
    "roles": KEYWORD,
    "urls": KEYWORD,
    "user": KEYWORD,
}

FILE_FIELDS: Final[NestedMappingType] = {
    "created": DATE,
    "description": KEYWORD_AND_TEXT,
    "device": KEYWORD,
    "directory": KEYWORD,
    "extension": KEYWORD,
    "hash": {"properties": HASH_FIELDS},
    "local_path": KEYWORD,
    "path": KEYWORD,
    "peat_module": KEYWORD,
    "gid": KEYWORD,
    "group": KEYWORD,
    "mime_type": KEYWORD,
    "mode": KEYWORD,
    "mtime": DATE,
    "name": KEYWORD,
    "original": BINARY,
    "owner": KEYWORD,
    "size": LONG,
    "target_path": KEYWORD,
    "type": KEYWORD,
    "uid": KEYWORD,
    "extra": FLATTENED,
}

FIRMWARE_FIELDS: Final[NestedMappingType] = {
    "checksum": KEYWORD,
    "extra": FLATTENED,
    "file": {"properties": FILE_FIELDS},
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "last_updated": DATE,
    "original": BINARY,
    "revision": KEYWORD,
    "release_date": DATE,
    "timestamp": DATE,
    "version": KEYWORD,
}

LOGIC_FIELDS: Final[NestedMappingType] = {
    "author": KEYWORD_AND_TEXT,
    "created": DATE,
    "description": KEYWORD_AND_TEXT,
    "file": {"properties": FILE_FIELDS},
    "formats": NESTED,
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "last_updated": DATE,
    "name": KEYWORD_AND_TEXT,
    "original": TEXT,
    "parsed": TEXT,
}

CERTENTITY_FIELDS: Final[MappingType] = {
    "common_name": KEYWORD,
    "country": KEYWORD,
    "distinguished_name": KEYWORD,
    "locality": KEYWORD,
    "organization": KEYWORD,
    "organizational_unit": KEYWORD,
    "state_or_province": KEYWORD,
}

X509_FIELDS: Final[NestedMappingType] = {
    "alternative_names": KEYWORD,
    "hash": {"properties": HASH_FIELDS},
    "issuer": {"properties": CERTENTITY_FIELDS},
    "not_after": DATE,
    "not_before": DATE,
    "original": KEYWORD,
    "public_key_algorithm": KEYWORD,
    "public_key_curve": KEYWORD,
    "public_key_exponent": LONG,
    "public_key_size": LONG,
    "serial_number": KEYWORD,
    "signature_algorithm": KEYWORD,
    "subject": {"properties": CERTENTITY_FIELDS},
    "version_number": KEYWORD,
}

SERVICE_FIELDS: Final[MappingType] = {
    "configured_port": LONG,
    "enabled": BOOL,
    "extra": FLATTENED,
    "listen_address": IP,
    "listen_interface": KEYWORD,
    "process_name": KEYWORD,
    "process_pid": LONG,
    "port": LONG,
    "protocol": KEYWORD,
    "protocol_id": KEYWORD,
    "role": KEYWORD,
    "status": KEYWORD,
    "transport": KEYWORD,
}

INTERFACE_FIELDS: Final[NestedMappingType] = {
    "alias": KEYWORD,
    "application": KEYWORD,
    "connected": BOOL,
    "description": {"properties": DESCRIPTION_FIELDS},
    "duplex": KEYWORD,
    "enabled": BOOL,
    "extra": FLATTENED,
    "name": KEYWORD,
    "type": KEYWORD,
    "hostname": KEYWORD,
    "mac": KEYWORD,
    "mac_vendor": KEYWORD_AND_TEXT,
    "mtu": INTEGER,
    "physical": BOOL,
    "promiscuous_mode": BOOL,
    "speed": INTEGER,
    "uptime": LONG,
    "hardware_mac": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "subnet_mask": IP,
    "gateway": IP,
    "serial_port": KEYWORD,
    "baudrate": INTEGER,
    "data_bits": BYTE,
    "parity": KEYWORD,
    "stop_bits": BYTE,
    "flow_control": KEYWORD,
    "services": {"properties": SERVICE_FIELDS},
    "version": KEYWORD,
}

REGISTER_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "data_type": KEYWORD,
    "description": TEXT,
    "enabled": BOOL,
    "extra": FLATTENED,
    "group": KEYWORD,
    "io": KEYWORD,
    "measurement_type": KEYWORD,
    "name": KEYWORD,
    "protocol": KEYWORD,
    "read_write": KEYWORD,
    "tag": KEYWORD,
}

TAG_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "description": TEXT,
    "io": KEYWORD,
    "name": KEYWORD,
    "type": KEYWORD,
}

IO_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "description": TEXT,
    "direction": KEYWORD,
    "extra": FLATTENED,
    "id": KEYWORD,
    "name": KEYWORD,
    "type": KEYWORD,
    "slot": KEYWORD,
}

ERROR_FIELDS: Final[MappingType] = {
    "code": KEYWORD,
    "id": KEYWORD,
    "message": TEXT,
    "stack_trace": TEXT,
    "type": KEYWORD,
}

GEO_FIELDS: Final[MappingType] = {
    "city_name": KEYWORD,
    "country_name": KEYWORD,
    "location": {"type": "geo_point"},
    "name": KEYWORD,
    "timezone": KEYWORD,
}

EVENT_FIELDS: Final[NestedMappingType] = {
    "action": KEYWORD,
    "category": KEYWORD,
    "created": DATE,
    "dataset": KEYWORD,
    "extra": FLATTENED,
    "hash": {"properties": HASH_FIELDS},
    "id": KEYWORD,
    "ingested": DATE,
    "kind": KEYWORD,
    "message": KEYWORD_AND_TEXT,
    "module": KEYWORD,
    "original": TEXT,
    "outcome": KEYWORD,
    "provider": KEYWORD,
    "sequence": LONG,
    "severity": LONG,
    "timezone": KEYWORD,
    "type": KEYWORD,
}

OS_FIELDS: Final[NestedMappingType] = {
    "family": KEYWORD,
    "full": KEYWORD,
    "kernel": KEYWORD,
    "name": KEYWORD,
    "timestamp": DATE,
    "vendor": {"properties": VENDOR_FIELDS},
    "version": KEYWORD,
}

MEMORY_FIELDS: Final[MappingType] = {
    "address": KEYWORD,
    "created": DATE,
    "dataset": KEYWORD,
    "device": KEYWORD,
    "process": KEYWORD,
    "size": LONG,
    "value": {
        "type": "keyword",
        "ignore_above": 4096,  # memory values can be quite large
    },
    "extra": FLATTENED,
}

SSHKEY_FIELDS: Final[NestedMappingType] = {
    "description": KEYWORD_AND_TEXT,
    "file": {"properties": FILE_FIELDS},
    "host": KEYWORD,
    "id": KEYWORD,
    "original": KEYWORD_AND_TEXT,
    "type": KEYWORD,
    "user": KEYWORD,
}

AGENT_FIELDS: Final[MappingType] = {
    "id": KEYWORD,
    "type": KEYWORD,
    "version": KEYWORD,
}

ECS_FIELDS: Final[MappingType] = {"version": KEYWORD}

OBSERVER_FIELDS: Final[NestedMappingType] = {
    "geo": {"properties": GEO_FIELDS},
    "hostname": KEYWORD,
    "interface": {"properties": {"name": KEYWORD, "egress": {"properties": {"name": KEYWORD}}}},
    "ip": IP,
    "mac": KEYWORD,
    "os": {"properties": OS_FIELDS},
    "user": {"properties": USER_FIELDS},
}

BASE_FIELDS: Final[NestedMappingType] = {
    "@timestamp": DATE,
    "agent": {"properties": AGENT_FIELDS},
    "ecs": {"properties": ECS_FIELDS},
    "message": TEXT,
    "observer": {"properties": OBSERVER_FIELDS},
    "tags": KEYWORD,
}
UEFI_FILE_FIELD: Final[MappingType] = {
    # Define all Fields
    "type": KEYWORD,
    "subtype": KEYWORD,
    "base": KEYWORD,
    "size": KEYWORD,
    "crc32": KEYWORD,
    "guid": KEYWORD,
    "name": KEYWORD,
    "path": KEYWORD,
    "created": DATE,
}

UEFI_HASH_FIELD: Final[MappingType] = {
    "file_system": KEYWORD,
    "pathname": KEYWORD,
    "hash": KEYWORD,
}
BASIC_HOST_FIELDS: Final[NestedMappingType] = {
    "description": {"properties": DESCRIPTION_FIELDS},
    "hostname": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "serial_port": KEYWORD,
    "name": KEYWORD,
    "type": KEYWORD,
    "slot": KEYWORD,
    "geo": {"properties": GEO_FIELDS},
}

HOST_FIELDS: Final[NestedMappingType] = {
    "architecture": KEYWORD,
    "boot_firmware": {"properties": FIRMWARE_FIELDS},
    "description": {"properties": DESCRIPTION_FIELDS},
    "endian": KEYWORD,
    "firmware": {"properties": FIRMWARE_FIELDS},
    "hardware": {"properties": HARDWARE_FIELDS},
    "hostname": KEYWORD,
    "id": KEYWORD,
    "ip": IP,
    "mac": KEYWORD,
    "mac_vendor": KEYWORD_AND_TEXT,
    "serial_port": KEYWORD,
    "name": KEYWORD,
    "label": KEYWORD,
    "comment": KEYWORD_AND_TEXT,
    "part_number": KEYWORD,
    "type": KEYWORD,
    "serial_number": KEYWORD,
    "manufacturing_date": DATE,
    "run_mode": KEYWORD,
    "slot": KEYWORD,
    "start_time": DATE,
    "status": KEYWORD,
    "uptime": LONG,
    "os": {"properties": OS_FIELDS},
    "geo": {"properties": GEO_FIELDS},
    "logic": {"properties": LOGIC_FIELDS},
    "interface": {"properties": INTERFACE_FIELDS},
    "service": {"properties": SERVICE_FIELDS},
    "ssh_keys": {"properties": SSHKEY_FIELDS},
    "related": {"properties": RELATED_FIELDS},
    "registers": {"properties": REGISTER_FIELDS},
    "tag": {"properties": TAG_FIELDS},
    "io": {"properties": IO_FIELDS},
    "event": {"properties": EVENT_FIELDS},
    "memory": {"properties": MEMORY_FIELDS},
    "users": {"properties": USER_FIELDS},
    "x509": {"properties": X509_FIELDS},
    "extra": FLATTENED,
    "uefi_image": {"properties": UEFI_FILE_FIELD},
    "uefi_hashes": {"properties": UEFI_HASH_FIELD},
}

PROCESS_FIELDS: Final[NestedMappingType] = {
    "args": KEYWORD,
    "args_count": LONG,
    "command_line": KEYWORD_AND_TEXT,
    "executable": KEYWORD_AND_TEXT,
    "name": KEYWORD_AND_TEXT,
    "parent": {"properties": {"pid": LONG}},
    "pgid": LONG,
    "pid": LONG,
    "start": DATE,
    "thread": {"properties": {"id": LONG, "name": KEYWORD}},
    "title": KEYWORD_AND_TEXT,
    "working_directory": KEYWORD_AND_TEXT,
}

PARSE_RESULT: Final[dict[str, NestedMappingType]] = {
    "properties": {
        "name": KEYWORD,
        "path": KEYWORD,
        "module": KEYWORD,
        "results": {"properties": {**HOST_FIELDS, "module": {"properties": HOST_FIELDS}}},
    }
}


# -- PEAT index mappings --
PEAT_INDICES: Final[dict[str, dict]] = {
    "peat-logs": {
        "properties": {
            **BASE_FIELDS,
            "error": {"properties": ERROR_FIELDS},
            "event": {"properties": EVENT_FIELDS},
            "log": {
                "properties": {
                    "level": KEYWORD,
                    "logger": KEYWORD,
                    "original": KEYWORD,
                    "origin": {
                        "properties": {
                            "function": KEYWORD,
                            "file": {"properties": {"line": LONG, "name": KEYWORD}},
                        }
                    },
                }
            },
            "peat": {
                "properties": {
                    "containerized": BOOL,
                    "debug_level": LONG,
                    "entrypoint": KEYWORD,
                    "podman": BOOL,
                    "python_version": KEYWORD,
                }
            },
            "process": {"properties": PROCESS_FIELDS},
        }
    },
    "peat-scan-summaries": {
        "properties": {
            **BASE_FIELDS,
            "peat_version": KEYWORD,
            "peat_run_id": KEYWORD,
            "scan_duration": DOUBLE,
            "scan_modules": KEYWORD,
            "scan_type": KEYWORD,
            # Targets could be IPs, IP ranges, serial ports, MACs, etc.
            # Therefore, we just use a plain ole' "keyword" type.
            "scan_targets": KEYWORD,
            "scan_original_targets": KEYWORD,
            "num_hosts_active": LONG,
            "num_hosts_online": LONG,
            "num_hosts_verified": LONG,
            "hosts_online": KEYWORD,
            "hosts_verified": FLATTENED,
        }
    },
    "peat-pull-summaries": {
        "properties": {
            **BASE_FIELDS,
            "peat_version": KEYWORD,
            "peat_run_id": KEYWORD,
            "pull_duration": DOUBLE,
            "pull_modules": KEYWORD,
            # Targets could be IPs, IP ranges, serial ports, MACs, etc.
            # Therefore, we just use a plain ole' "keyword" type.
            "pull_targets": KEYWORD,
            "pull_original_targets": KEYWORD,
            "pull_devices": KEYWORD,
            "pull_comm_type": KEYWORD,
            "num_pull_results": LONG,
            "pull_results": FLATTENED,
        }
    },
    "peat-parse-summaries": {
        "properties": {
            **BASE_FIELDS,
            "peat_version": KEYWORD,
            "peat_run_id": KEYWORD,
            "parse_duration": DOUBLE,
            "parse_modules": KEYWORD,
            "input_paths": KEYWORD,
            "files_parsed": KEYWORD,
            "num_files_parsed": LONG,
            "num_parse_successes": LONG,
            "num_parse_failures": LONG,
            "parse_failures": PARSE_RESULT,
            "parse_results": PARSE_RESULT,
        }
    },
    "peat-configs": {
        "properties": {
            **BASE_FIELDS,
        }
    },
    "peat-state": {
        "properties": {
            **BASE_FIELDS,
        }
    },
    "ot-device-hosts-timeseries": {
        "properties": {
            **BASE_FIELDS,
            "host": {
                "properties": {
                    **HOST_FIELDS,
                    "module": {"properties": HOST_FIELDS},
                }
            },
        }
    },
    "ot-device-files": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "file": {"properties": FILE_FIELDS},
        }
    },
    "ot-device-registers": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "register": {"properties": REGISTER_FIELDS},
        }
    },
    "ot-device-tags": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "tag": {"properties": TAG_FIELDS},
        }
    },
    "ot-device-io": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "io": {"properties": IO_FIELDS},
        }
    },
    "ot-device-events": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
        }
    },
    "ot-device-memory": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "memory": {"properties": MEMORY_FIELDS},
        }
    },
    "uefi-files": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "uefi": {"properties": UEFI_FILE_FIELD},
        }
    },
    "uefi-hashes": {
        "properties": {
            **BASE_FIELDS,
            "event": {"properties": EVENT_FIELDS},
            "host": {"properties": BASIC_HOST_FIELDS},
            "uefi": {"properties": UEFI_HASH_FIELD},
        }
    },
}
