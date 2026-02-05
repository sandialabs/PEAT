import inspect
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from peat import config, module_api


def get_modules() -> list[str]:
    return module_api.names


def get_pull_methods(module: str) -> list[str]:
    for attr, value in inspect.getmembers(module_api.get_module(module)):
        if attr == "default_options":
            for option in value.values():
                if "pull_methods" in option:
                    return option["pull_methods"]
    return None


def get_default_options(module: str) -> dict[str, Any]:
    for attr, value in inspect.getmembers(module_api.get_module(module)):
        if attr == "default_options":
            return value
    return None


def convert_tuples_to_dict(
    data: list | tuple | dict | Any | None,
) -> list | dict | Any | None:
    """Converts python tuples to dicts because YAML doesn't understand what that is."""
    if isinstance(data, list):
        # If the data is a list, iterate through its elements
        return [convert_tuples_to_dict(item) for item in data]
    elif isinstance(data, tuple):
        # If the data is a tuple, convert it to a dictionary
        if len(data) == 2:
            return {data[0]: data[1]}  # Convert tuple to dict with key-value pair
        else:
            return list(data)  # If tuple has more than 2 elements, return as list
    elif isinstance(data, dict):
        # If the data is a dictionary, recursively process its values
        return {key: convert_tuples_to_dict(value) for key, value in data.items()}
    else:
        # If it's neither a list, tuple, nor dict, return it as is
        return data


# API calls
# 'hosts' argument: list of hosts in the format (ip, label, PEAT module)
# TODO: currently only pulls default options from PEAT repo, which may
# not include defaults for every pull method depending on how they were
# written. Need to call get_pull_methods(module), then autogenerate templates
# for every pull method without a module-provided default option.


def generate_simple_config(hosts: list[tuple]) -> str:
    yaml_config = {
        "metadata": {
            "name": "autobuilt_config_" + str(date.today()),
            "description": "autobuilt config",
            "author": "Parseus",
            "created": date.today(),
            "updated": date.today(),
        },
        "additional_modules": [],
        "debug": 0,
        "env_prefix": "PEAT_CONFIG_",
        "hash_algorithms": ["md5", "sha1", "sha256", "sha512"],
        "verbose": False,
        "quiet": False,
        "assume_online": False,
        "max_threads": 200,
        "default_timeout": 5.0,
        "force_online_method_ping": False,
        "force_online_method_tcp": False,
        "icmp_fallback_tcp_syn": False,
        "syn_port": 80,
        "push_skip_scan": False,
        "intensive_scan": False,
    }

    # Manually setting this dictionary mapping in case it needs convert_tuples_to_dict
    # functionality over more than just default options (Parseus compatibility)
    # or particular host ordering
    yaml_config["hosts"] = []
    for host in hosts:
        config_data = {
            "label": host[1],
            "identifiers": {"ip": host[0]},
            "peat_module": host[2],
            "options": get_default_options(host[2]),
        }
        config_data = convert_tuples_to_dict(config_data)
        yaml_config["hosts"].append(config_data)

    # Potential refactor:
    # [{
    #        "label": host[1],
    #        "identifiers": {"ip": host[0]},
    #        "peat_module": host[2],
    #        "options": convert_tuples_to_dict(get_default_options(host[2])),
    #  } for host in hosts]

    return yaml.dump(yaml_config)


def generate_full_config(hosts: list[tuple]) -> str:

    yaml_config = {}

    for attr, value in inspect.getmembers(config):
        if not attr.startswith("_"):
            if not inspect.isroutine(value):
                if isinstance(value, Path):
                    yaml_config[attr.lower()] = str(value)
                else:
                    yaml_config[attr.lower()] = value

    for host in hosts:
        yaml_config["hosts"].append(
            {
                "label": host[1],
                "identifiers": {"ip": host[0]},
                "peat_module": host[2],
                "options": get_default_options(host[2]),
            }
        )

    yaml_config["metadata"]["created"] = date.today()
    yaml_config["metadata"]["updated"] = date.today()

    return yaml.dump(yaml_config)
