"""
PEAT Module for OpenPLC Runtime v4

This module allows PEAT to discover, fingerprint, pull data from, and push
programs to an OpenPLC Runtime v4 by interacting with its web API.
---
Usage Examples:
# 1. Scan for OpenPLC Runtime v4 instances
peat scan -i 192.168.1.0/24 -I ./openplcv4.py
# 2. Pull data from a discovered OpenPLC instance
peat pull -i 192.168.1.50 -d openplcv4 -I ./openplcv4.py -c ./config.yaml
# 3. Push a new PLC program to the device
peat push -i 192.168.1.50 -d openplcv4 -I ./openplcv4.py -c ./config.yaml -- ./program.zip
"""
import json
import requests
from pathlib import Path

# Suppress warnings from urllib3 for insecure/self-signed SSL connections
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# PEAT Core Imports
from peat import (
    DeviceData,
    DeviceModule,
    Service,
    User,
    Event,
    File,
    utils,
    IPMethod
)

"""PEAT Module for interacting with the OpenPLC Runtime v4 API over HTTPS."""
class OpenPLCv4(DeviceModule):
    device_type = "PLC"
    vendor_id = "Autonomy"
    vendor_name = "Autonomy Logic, Inc."
    module_aliases = ["open", "openplc", "openplcv4", "autonomy"]
    filename_patterns = ["openplc_output.json"]
    default_options = {
        "openplcv4": {
            "username": "",
            "password": "",
            "pull_methods": ["https"],
            "clean_upload": True,
            "plugins_to_query": [],
        },
        "https": {
            "port": 8443,
            "ssl": True
        }
    }

    """Logs into the OpenPLC API via HTTPS and stores the access token."""
    @classmethod
    def _login(cls, dev: DeviceData, session: requests.Session) -> bool:
        username = dev.options["openplcv4"]["username"]
        password = dev.options["openplcv4"]["password"]
        port = dev.options.get("https", {}).get("port", 8443)
        api_url = f"https://{dev.ip}:{port}/api"
        
        # Avoid redundant login if session is already established and valid
        if dev.extra.get('api_session') and dev.extra.get('api_url') == api_url:
            cls.log.debug("Using existing authenticated session.")
            return True

        cls.log.debug(f"Using API URL: {api_url}")
        cls.log.debug(f"Attempting login with username: '{username}'")
        login_payload = {'username': username, 'password': password}
        try:
            cls.log.info(f"Attempting to log in to {dev.ip} over HTTPS as '{username}'...")
            response = session.post(f"{api_url}/login", json=login_payload, verify=False, timeout=10)
            if response.status_code == 200:
                access_token = response.json().get('access_token')
                if access_token:
                    cls.log.debug("Login successful, access token received.")
                    session.headers.update({'Authorization': f'Bearer {access_token}'})
                    dev.extra['api_session'] = session
                    dev.extra['api_url'] = api_url
                    return True
                else:
                    cls.log.warning("Login successful, but no access token was provided by the server.")
                    return False
            else:
                cls.log.warning(f"Login failed for {dev.ip}. HTTP {response.status_code}. Check credentials.")
                cls.log.debug(f"Failed login response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            cls.log.error(f"Error during login to {dev.ip}: {e}")
            return False

    """Helper to make authenticated API requests (GET and POST) over HTTPS."""
    @classmethod
    def _make_api_request(cls, dev: DeviceData, method: str, endpoint: str, params=None, files=None, json_payload=None, **kwargs) -> dict | None:
        session = dev.extra.get('api_session')
        api_url = dev.extra.get('api_url')
        if not session or not api_url:
            cls.log.error("API session not initialized. Cannot make request.")
            return None
        url = f"{api_url}/{endpoint}"
        cls.log.debug(f"Making {method} request to: {url}")
        kwargs.setdefault('timeout', 60 if method.upper() == 'POST' else 10)
        kwargs.setdefault('verify', False)
        try:
            if method.upper() == 'GET':
                response = session.get(url, params=params, **kwargs)
            elif method.upper() == 'POST':
                response = session.post(url, params=params, json=json_payload, files=files, **kwargs)
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

    """Pushes a program to the OpenPLC runtime."""
    @classmethod
    def _push(cls, dev: DeviceData, file: Path, push_type: str | None = None) -> bool:
        session = requests.Session()
        if not cls._login(dev, session):
            cls.log.error(f"Push failed for {dev.ip}: Could not authenticate to the API.")
            return False
        cls.log.info(f"Initiating push of program '{file.name}' to {dev.ip}.")
        clean_upload = dev.options["openplcv4"].get("clean_upload", False)
        try:
            with open(file, 'rb') as f:
                response = cls._make_api_request(
                    dev, 'POST', 'upload-file',
                    params={'clean': '1'} if clean_upload else None,
                    files={'file': (file.name, f)},
                    timeout=60
                )
                if response:
                    cls.log.info(f"Successfully pushed program '{file.name}' to {dev.ip}.")
                    dev.store("event", Event(action="file_push", outcome="success", message=f"Pushed PLC program '{file.name}'."))
                    return True
                else:
                    cls.log.error(f"Failed to push program '{file.name}' to {dev.ip}.")
                    dev.store("event", Event(action="file_push", outcome="failure", message=f"Failed to push PLC program '{file.name}'."))
                    return False
        except FileNotFoundError:
            cls.log.error(f"Push failed: File not found at '{file}'")
            return False
        except Exception as e:
            cls.log.error(f"An unexpected error occurred during file push: {e}")
            return False

    """Pulls and parses data from the OpenPLCv4 API."""
    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        if "https" not in dev.options["openplcv4"]["pull_methods"]:
            cls.log.info("Skipping OpenPLC pull: 'https' not in pull_methods.")
            return True
        session = requests.Session()
        if not cls._login(dev, session):
            cls.log.error(f"Pull failed for {dev.ip}: Could not authenticate to the API.")
            return False
        cls.log.info("Authentication successful. Starting data pull from API endpoints...")
        
        status_data = cls._make_api_request(dev, 'GET', 'status?include_stats=true')
        users_data = cls._make_api_request(dev, 'GET', 'get-users-info')
        logs_data = cls._make_api_request(dev, 'GET', 'runtime-logs')
        compilation_data = cls._make_api_request(dev, 'GET', 'compilation-status')

        if status_data:
            status_string = status_data.get('status', 'Unknown')
            dev.run_mode = status_string.replace("STATUS:", "").strip().upper() if "STATUS:" in status_string else status_string.upper()
            dev.status = "Online" if dev.run_mode == "RUNNING" else "Offline"
            if status_data.get('plc_file'):
                dev.logic.name = Path(status_data['plc_file']).name
                dev.store("files", File(name=Path(status_data['plc_file']).name, description="Currently loaded PLC program"))
            if 'timing_stats' in status_data:
                dev.extra['timing_stats'] = status_data['timing_stats']
                program_name = status_data['timing_stats'].get('name')
                if program_name:
                    dev.logic.name = program_name
            cls.log.info("Successfully retrieved PLC status with stats")

        if users_data and isinstance(users_data, list):
            for user_info in users_data:
                peat_user = User(
                    name=user_info.get('username'),
                    roles=set([user_info.get('role')]) if user_info.get('role') else set(),
                    id=str(user_info.get('id'))
                )
                dev.store('users', peat_user)
            cls.log.info("Successfully retrieved users")

        if logs_data and 'runtime-logs' in logs_data:
            log_content = ""
            for log_entry in logs_data['runtime-logs']:
                peat_event = Event(
                    created=utils.parse_date(log_entry.get('timestamp')),
                    message=log_entry.get('message'),
                    severity=log_entry.get('level'),
                    id=str(log_entry.get('id')),
                    dataset="runtime"
                )
                dev.store('event', peat_event)
                log_content += f"[{log_entry.get('level')}][ID: {log_entry.get('id')}] {log_entry.get('timestamp')}: {log_entry.get('message')}\n"
            dev.write_file(log_content, "openplc_runtime.log")
            dev.store("files", File(name="openplc_runtime.log", description="Runtime Logs"))
            cls.log.info("Successfully retrieved PLC log file")

        if compilation_data:
            comp_content = f"Status: {compilation_data.get('status', 'N/A')}\n"
            comp_content += f"Exit Code: {compilation_data.get('exit_code', 'N/A')}\n---\n"
            comp_content += "\n".join(compilation_data.get('logs', []))
            dev.write_file(comp_content, "compilation_status.log")
            dev.store("files", File(name="compilation_status.log", description="Last Compilation Status"))
            cls.log.info("Successfully retrieved PLC program compilation log file")
            
        plugins_to_query = dev.options.get("openplcv4", {}).get("plugins_to_query", {})
        if plugins_to_query:
            cls.log.info(f"Querying plugins: {', '.join(plugins_to_query.keys())}")
            if 'plugin_status' not in dev.extra:
                dev.extra['plugin_status'] = {}
            for plugin_name, command in plugins_to_query.items():
                cls.log.debug(f"Sending command: '{command}' to plugin: '{plugin_name}'...")
                payload = {
                    "plugin": plugin_name,
                    "command": command,
                    "params": {}
                }
                plugin_data = cls._make_api_request(dev, 'POST', 'plugin-command', json_payload=payload)
                if plugin_data:
                    cls.log.info(f"Successfully retrieved data for plugin '{plugin_name}' (Command: {command}).")
                    dev.extra['plugin_status'][plugin_name] = plugin_data
                    file_content = json.dumps(plugin_data, indent=2)
                    filename = f"{plugin_name}_{command}.json"
                    dev.write_file(file_content, filename)
                    dev.store("files", File(name=filename, description=f"Output for {plugin_name} plugin ({command})"))
                else:
                    cls.log.warning(f"Failed to execute command '{command}' on plugin '{plugin_name}'.")

        dev.successful_pulls["openplc_api"] = True
        return True

    """Verifies the device is an OpenPLCv4 instance by checking the /api/version endpoint via HTTPS."""
    @classmethod
    def _verify_https_api(cls, dev: DeviceData) -> bool:
        port = dev.options.get("https", {}).get("port", 8443)
        url = f"https://{dev.ip}:{port}/api/version"
        cls.log.debug(f"Checking for OpenPLCv4 API at {url}")
        try:
            response = requests.get(url, verify=False, timeout=5)
            if response.status_code == 200:
                version_data = response.json()
                if "version" in version_data:
                    cls.log.info(f"Verified OpenPLC Runtime {version_data['version']} on {dev.ip}")
                    dev.os.name = "OpenPLC Runtime v4"
                    dev.os.version = version_data['version']
                    dev.os.vendor.name = "Autonomy Logic, Inc."
                    dev.description.product = "OpenPLC Runtime v4"
                    dev.description.model = f"{version_data['version']}"
                    dev.store("service", Service(protocol="openplc-api", port=port, status="verified", transport="tcp"))
                    return True
            cls.log.debug(f"No valid OpenPLC API response from {dev.ip}. Status: {response.status_code}, Body: {response.text}")
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
        name="openplc_v4_https_api_check",
        description="Checks for the OpenPLCv4 /api/version endpoint over HTTPS.",
        type="unicast_ip",
        identify_function=OpenPLCv4._verify_https_api,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=8443,
    )
]
OpenPLCv4.serial_methods = []

__all__ = ["OpenPLCv4"]
