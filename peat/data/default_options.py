from peat import config

ConfigVal = list | str | bool | float | int

#: Global defaults used by all devices
#: Refer to examples/peat-config.yaml for descriptions of the options
DEFAULT_OPTIONS: dict[str, dict[str, ConfigVal] | ConfigVal] = {
    "baudrates": [],
    "timeout": config.DEFAULT_TIMEOUT,
    "sceptre_plc_compatible_st_logic": False,
    "ftp": {"port": 21, "timeout": config.DEFAULT_TIMEOUT},
    "telnet": {
        "port": 23,
        "timeout": config.DEFAULT_TIMEOUT,
        "meter_pass": "0",
        "pull_delay": 0,
    },
    "ssh": {
        "port": 22,
        "timeout": config.DEFAULT_TIMEOUT,
        "user": "",
        "pass": "",
        "passphrase": "",
        "key_filename": "",
        "look_for_keys": False,
    },
    "http": {"port": 80, "timeout": config.DEFAULT_TIMEOUT},
    "https": {"port": 443, "timeout": config.DEFAULT_TIMEOUT},
    "snmp": {
        "port": 161,
        "timeout": config.DEFAULT_TIMEOUT,
        "community": "public",
        "communities": ["public", "private"],
    },
    "serial": {
        "baudrate": 0,
        "timeout": config.DEFAULT_TIMEOUT,
    },
    "modbus_tcp": {"port": 502, "timeout": config.DEFAULT_TIMEOUT},
    "servlink_tcp": {"port": 666, "timeout": config.DEFAULT_TIMEOUT},
    "servlink_serial": {"timeout": config.DEFAULT_TIMEOUT},
    "postgres": {"port": 5432, "timeout": config.DEFAULT_TIMEOUT},
    "ion_protocol": {
        "port": 7700,
        "timeout": config.DEFAULT_TIMEOUT,
        "pull_ion_log": True,
        "pull_ion_config": True,
        "authenticated": False,
        "advanced_security": False,
        "user": "0",
        "pass": "0",
    },
    "cip": {
        # Common Industrial Protocol (CIP)
        "port": 44818,
        "timeout": config.DEFAULT_TIMEOUT,
    },
    "digsi": {
        # Siemens SIPROTEC DIGSI protocol
        "port": 50000,
        "timeout": config.DEFAULT_TIMEOUT,
    },
}
