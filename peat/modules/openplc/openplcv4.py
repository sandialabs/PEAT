"""
PEAT Module for OpenPLC Runtime v4

This module allows PEAT to discover, fingerprint, pull data from, and push
programs to an OpenPLC Runtime v4 by interacting with its web API.
---
Usage Examples:
# 1. Scan for OpenPLC Runtime v4 instances
pdm run peat scan -i 192.168.1.0/24
# 2. Pull data from a discovered OpenPLC instance
pdm run peat pull -i 192.168.1.50 -c ./examples/openplc-config.yaml
# 3. Push a new PLC program to the device
pdm run peat push -d openplcv4 -i 192.168.1.50 -c ./examples/openplc-config.yaml -- ./program.zip
"""

import json
from pathlib import Path

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# PEAT Core Imports
from peat import (
    DeviceData,
    DeviceModule,
    Event,
    File,
    Interface,
    IPMethod,
    Service,
    User,
    utils,
)

# Suppress warnings from urllib3 for insecure/self-signed SSL connections
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class OpenPLCv4(DeviceModule):
    """PEAT Module for interacting with the OpenPLC Runtime v4 API over HTTPS."""

    device_type = "PLC"
    vendor_id = "Autonomy"
    vendor_name = "Autonomy Logic, Inc."
    module_aliases = ["open", "openplc"]
    default_options = {
        "openplcv4": {
            "username": "",
            "password": "",
            "pull_methods": ["https"],
            "clean_upload": True,
            "plugins_to_query": {},
        },
        "https": {
            "port": 8443,
            "ssl": True,
        },  # Hardcoded default https port for OpenPLC Runtime v4
    }

    @classmethod
    def _login(cls, dev: DeviceData, session: requests.Session) -> bool:
        """Logs into the OpenPLC API via HTTPS and stores the access token."""
        username = dev.options["openplcv4"]["username"]
        password = dev.options["openplcv4"]["password"]
        port = dev.options["https"]["port"]
        api_url = f"https://{dev.ip}:{port}/api"

        # Avoid redundant login if session is already established and valid
        if dev._cache.get("api_session") and dev._cache.get("api_url") == api_url:
            cls.log.debug("Using existing authenticated session.")
            return True

        cls.log.debug(f"Using API URL: {api_url}")
        cls.log.debug(f"Attempting login with username: '{username}'")
        login_payload = {"username": username, "password": password}

        try:
            cls.log.info(f"Attempting to log in to {dev.ip} over HTTPS as '{username}'...")
            response = session.post(
                f"{api_url}/login", json=login_payload, verify=False, timeout=10
            )
            if response.status_code == 200:
                access_token = response.json().get("access_token")
                if access_token:
                    cls.log.debug("Login successful, access token received.")
                    session.headers.update({"Authorization": f"Bearer {access_token}"})
                    dev._cache["api_session"] = session
                    dev._cache["api_url"] = api_url
                    return True
                else:
                    cls.log.warning(
                        "Login successful, \
                        but no access token was provided by the server."
                    )
                    return False
            else:
                cls.log.warning(
                    f"Login failed for {dev.ip}. HTTP {response.status_code}. Check credentials."
                )
                cls.log.debug(f"Failed login response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            cls.log.error(f"Error during login to {dev.ip}: {e}")
            return False

    @classmethod
    def _make_api_request(
        cls,
        dev: DeviceData,
        method: str,
        endpoint: str,
        params: dict[str, object] | None = None,
        files: dict[str, object] | None = None,
        json_payload: dict[str, object] | None = None,
        **kwargs,
    ) -> dict[str, object] | None:
        """Helper to make authenticated API requests (GET and POST) over HTTPS."""
        session = dev._cache.get("api_session")
        api_url = dev._cache.get("api_url")

        if not session or not api_url:
            cls.log.error("API session not initialized. Cannot make request.")
            return None

        url = f"{api_url}/{endpoint}"
        cls.log.debug(f"Making {method} request to: {url}")
        kwargs.setdefault("timeout", 60 if method.upper() == "POST" else 10)
        kwargs.setdefault("verify", False)

        try:
            if method.upper() == "GET":
                response = session.get(url, params=params, **kwargs)
            elif method.upper() == "POST":
                response = session.post(
                    url, params=params, json=json_payload, files=files, **kwargs
                )
            else:
                cls.log.error(f"Unsupported HTTP method '{method}'")
                return None
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.HTTPError as e:
            cls.log.warning(f"HTTP Error for {method} request to '{endpoint}' on {dev.ip}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            cls.log.error(f"Network error for {method} request to '{endpoint}' on {dev.ip}: {e}")
            return None

    @classmethod
    def _push(cls, dev: DeviceData, file: Path, _push_type: str) -> bool:
        """Pushes a program to the OpenPLC runtime."""
        session = requests.Session()

        if not cls._login(dev, session):
            cls.log.error(f"Push failed for {dev.ip}: Could not authenticate to the API.")
            return False

        cls.log.info(f"Initiating push of program '{file.name}' to {dev.ip}")
        clean_upload = dev.options["openplcv4"]["clean_upload"]

        try:
            with open(file, "rb") as f:
                response = cls._make_api_request(
                    dev,
                    "POST",
                    "upload-file",
                    params={"clean": "1"} if clean_upload else None,
                    files={"file": (file.name, f)},
                    timeout=60,
                )
                if response:
                    cls.log.info(f"Successfully pushed program '{file.name}' to {dev.ip}")
                    dev.store(
                        "event",
                        Event(
                            action="file_push",
                            outcome="success",
                            message=f"Pushed PLC program '{file.name}'",
                        ),
                    )
                    return True
                else:
                    cls.log.error(f"Failed to push program '{file.name}' to {dev.ip}")
                    dev.store(
                        "event",
                        Event(
                            action="file_push",
                            outcome="failure",
                            message=f"Failed to push PLC program '{file.name}'",
                        ),
                    )
                    return False
        except FileNotFoundError:
            cls.log.error(f"Push failed: File not found at '{file}'")
            return False
        except Exception as e:
            cls.log.error(f"An unexpected error occurred during file push: {e}")
            return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """Pulls and parses data from the OpenPLCv4 API."""
        if "https" not in dev.options["openplcv4"]["pull_methods"]:
            cls.log.info("Skipping OpenPLC pull: 'https' not in pull_methods.")
            return True

        session = requests.Session()

        if not cls._login(dev, session):
            cls.log.error(f"Pull failed for {dev.ip}: Could not authenticate to the API.")
            return False
        cls.log.info("Authentication successful. Starting data pull from API endpoints...")

        status_data = cls._make_api_request(dev, "GET", "status?include_stats=true")
        users_data = cls._make_api_request(dev, "GET", "get-users-info")
        logs_data = cls._make_api_request(dev, "GET", "runtime-logs")
        compilation_data = cls._make_api_request(dev, "GET", "compilation-status")
        serial_data = cls._make_api_request(dev, "GET", "serial-ports")

        if status_data:
            status_string = status_data.get("status", "Unknown")
            dev.run_mode = (
                status_string.replace("STATUS:", "").strip().upper()
                if "STATUS:" in status_string
                else status_string.upper()
            )
            dev.status = "Online" if dev.run_mode == "RUNNING" else "Offline"
            if status_data.get("plc_file"):
                dev.logic.name = Path(status_data["plc_file"]).name
                dev.store(
                    "files",
                    File(
                        name=Path(status_data["plc_file"]).name,
                        description="Currently loaded PLC program",
                    ),
                )
            if "timing_stats" in status_data:
                dev.extra["timing_stats"] = status_data["timing_stats"]
                program_name = status_data["timing_stats"].get("name")
                if program_name:
                    dev.logic.name = program_name
            cls.log.info("Successfully retrieved PLC status with stats")

        if users_data and isinstance(users_data, list):
            for user_info in users_data:
                peat_user = User(
                    name=user_info.get("username"),
                    roles={user_info.get("role")} if user_info.get("role") else set(),
                    id=str(user_info.get("id")),
                )
                dev.store("users", peat_user)
            cls.log.info("Successfully retrieved users")

        if logs_data and "runtime-logs" in logs_data:
            log_content = ""
            for log_entry in logs_data["runtime-logs"]:
                peat_event = Event(
                    created=utils.parse_date(log_entry.get("timestamp")),
                    message=log_entry.get("message"),
                    severity=log_entry.get("level"),
                    id=str(log_entry.get("id")),
                    dataset="runtime",
                )
                dev.store("event", peat_event)
                log_content += f"[{log_entry.get('level')}][ID: {log_entry.get('id')}] \
                    {log_entry.get('timestamp')}: {log_entry.get('message')}\n"
            dev.write_file(log_content, "openplc_runtime.log")
            dev.store("files", File(name="openplc_runtime.log", description="Runtime Logs"))
            cls.log.info("Successfully retrieved PLC log file")

        if compilation_data:
            comp_content = f"Status: {compilation_data.get('status', 'N/A')}\n"
            comp_content += f"Exit Code: {compilation_data.get('exit_code', 'N/A')}\n---\n"
            comp_content += "\n".join(compilation_data.get("logs", []))
            dev.write_file(comp_content, "compilation_status.log")
            dev.store(
                "files", File(name="compilation_status.log", description="Last Compilation Status")
            )
            cls.log.info("Successfully retrieved PLC program compilation log file")

        # Pull available serial ports from device and store as interfaces
        if serial_data and isinstance(serial_data.get("ports"), list):
            ports = serial_data.get("ports", [])
            for port_info in ports:
                port_name = port_info.get("device")
                if port_name:
                    serial = Interface(
                        type="serial",
                        serial_port=port_name,
                        name=port_info.get("description"),
                    )
                    dev.store("interface", serial)
            cls.log.info("Successfully retrieved available serial ports")

        plugins_to_query = dev.options.get("openplcv4", {}).get("plugins_to_query", {})
        if plugins_to_query:
            cls.log.info(f"Querying plugins: {', '.join(plugins_to_query.keys())}")

            if "plugin_status" not in dev.extra:
                dev.extra["plugin_status"] = {}

            for plugin_name, command in plugins_to_query.items():
                cls.log.debug(f"Sending command: '{command}' to plugin: '{plugin_name}'...")
                payload = {"plugin": plugin_name, "command": command, "params": {}}
                plugin_data = cls._make_api_request(
                    dev, "POST", "plugin-command", json_payload=payload
                )
                if plugin_data:
                    cls.log.info(
                        f"Successfully retrieved plugin data: '{plugin_name}' ({command})"
                    )
                    dev.extra["plugin_status"][plugin_name] = plugin_data
                    file_content = json.dumps(plugin_data, indent=2)
                    filename = f"{plugin_name}_{command}.json"
                    dev.write_file(file_content, filename)
                    dev.store(
                        "files",
                        File(
                            name=filename,
                            description=f"Output for {plugin_name} plugin ({command})",
                        ),
                    )
                else:
                    cls.log.warning(
                        f"Failed to execute command '{command}' \
                        on plugin '{plugin_name}'"
                    )

        dev.successful_pulls["openplc_api"] = True
        return True

    @classmethod
    def _verify_https_api(cls, dev: DeviceData) -> bool:
        """Verifies the device is an OpenPLCv4 instance by checking the /api/version endpoint."""
        port = dev.options["https"]["port"]
        url = f"https://{dev.ip}:{port}/api/version"
        cls.log.debug(f"Checking for OpenPLCv4 API at {url}")

        try:
            response = requests.get(url, verify=False, timeout=5)
            if response.status_code == 200:
                version_data = response.json()
                if "version" in version_data:
                    cls.log.info(f"Verified OpenPLC Runtime {version_data['version']} on {dev.ip}")
                    dev.os.name = "OpenPLC Runtime v4"
                    dev.os.version = version_data["version"]
                    dev.os.vendor.name = "Autonomy Logic, Inc."
                    dev.description.product = "OpenPLC Runtime v4"
                    dev.description.model = f"{version_data['version']}"
                    dev.store(
                        "service",
                        Service(
                            protocol="openplc_api", port=port, status="verified", transport="tcp"
                        ),
                    )
                    return True
            cls.log.debug(
                f"No valid OpenPLC API response from {dev.ip}. \
                Status: {response.status_code}, Body: {response.text}"
            )
            return False
        except requests.exceptions.RequestException as e:
            cls.log.debug(f"Failed to verify OpenPLCv4 at {dev.ip} via HTTPS API: {e}")
            return False
        except Exception as e:
            cls.log.debug(f"An unexpected error occurred during verification at {dev.ip}: {e}")
            return False


# --- Identification Methods ---
OpenPLCv4.ip_methods = [
    IPMethod(
        name="OpenPLC Runtime v4 HTTPS REST API",
        description="Checks for the OpenPLCv4 /api/version endpoint over HTTPS.",
        type="unicast_ip",
        identify_function=OpenPLCv4._verify_https_api,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=8443,
    ),
]
OpenPLCv4.serial_methods = []

__all__ = ["OpenPLCv4"]
