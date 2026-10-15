"""
PEAT Module for OpenPLC Runtime v3

OpenPLC Runtime v3 has no REST API. Its configuration and status are only
exposed through the Flask web interface (HTTP, port 8080 by default), so this
module logs in with a normal form login and reads the HTML pages.

The module is read-only: it never starts/stops the runtime, uploads programs,
or changes settings. It only issues GET requests after login.

OpenPLC v3 is the runtime used by GRFICSv3 and many other training labs.
See :doc:`grfics_tutorial` for an end-to-end walkthrough.
---
Usage Examples:
# 1. Scan for OpenPLC Runtime v3 instances
pdm run peat scan -d openplcv3 -i 192.168.95.0/24
# 2. Pull data from an OpenPLC v3 instance
pdm run peat pull -d openplcv3 -i 192.168.95.2 -c ./examples/peat-config-grfics.yaml
"""

import re

import requests
from bs4 import BeautifulSoup

from peat import (
    DeviceData,
    DeviceModule,
    File,
    IPMethod,
    Service,
    Tag,
    User,
    utils,
)

RELEASE_RE = re.compile(r"Release:\s*([0-9A-Za-z.\-_]+)")

# Settings page checkbox id -> (protocol name, port input id, transport)
SETTINGS_SERVICES = {
    "modbus_server": ("modbus_tcp", "modbus_server_port", "tcp"),
    "dnp3_server": ("dnp3", "dnp3_server_port", "tcp"),
    "enip_server": ("enip", "enip_server_port", "tcp"),
}


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def _table_rows(html: str) -> list[tuple[list[str], str]]:
    """
    Returns the data rows of the first table on a page as a list of
    (cell text list, onclick attribute). Header rows are skipped.
    """
    rows = []
    for tr in _soup(html).find_all("tr"):
        if tr.find("th"):
            continue
        cells = [td.get_text(strip=True) for td in tr.find_all("td")]
        if cells:
            rows.append((cells, tr.get("onclick", "")))
    return rows


def _table_id(onclick: str) -> str:
    match = re.search(r"table_id=(\d+)", onclick)
    return match.group(1) if match else ""


# --- Standalone Data Processors ---
def parse_login_page(html: str) -> str | None:
    """
    Checks if a page is the OpenPLC v3 login page.

    Returns:
        The release string (e.g. ``"2025-03-31"``), ``""`` if it's OpenPLC
        but no release is shown, or :obj:`None` if it's not OpenPLC v3.
    """
    if "OpenPLC" not in html:
        return None
    soup = _soup(html)
    if not soup.find("input", attrs={"name": "username"}) or not soup.find(
        "input", attrs={"name": "password"}
    ):
        return None
    match = RELEASE_RE.search(soup.get_text(" "))
    return match.group(1) if match else ""


def process_dashboard(html: str, dev: DeviceData) -> None:
    """Run mode and the currently loaded program."""
    fields = {}
    for p in _soup(html).find_all("p"):
        text = p.get_text(" ", strip=True)
        if not p.find("b") or ":" not in text:
            continue
        key, value = (x.strip() for x in text.split(":", 1))
        key = key.lower()
        if key in ("status", "program", "description", "file", "runtime"):
            fields.setdefault(key, value)

    if fields.get("status"):
        dev.run_mode = fields["status"].upper()
        dev.status = "Online"
    if fields.get("program"):
        dev.logic.name = fields["program"]
    if fields.get("description"):
        dev.logic.description = fields["description"]
    if fields.get("file"):
        dev.logic.file.name = fields["file"]
        dev.related.files.add(fields["file"])
    if fields.get("runtime"):
        dev.extra["runtime"] = fields["runtime"]


def process_programs(html: str, dev: DeviceData) -> None:
    """Programs that have been uploaded to the runtime."""
    programs = []
    for cells, onclick in _table_rows(html):
        if len(cells) < 3:
            continue
        programs.append(
            {
                "id": _table_id(onclick),
                "name": cells[0],
                "file": cells[1],
                "date_uploaded": cells[2],
            }
        )
        dev.related.files.add(cells[1])
    if programs:
        dev.extra["programs"] = programs


def process_users(html: str, dev: DeviceData) -> None:
    """Web interface user accounts (passwords are not collected)."""
    for cells, onclick in _table_rows(html):
        if len(cells) < 2:
            continue
        email = cells[2] if len(cells) > 2 else ""
        dev.store(
            "users",
            User(id=_table_id(onclick), full_name=cells[0], name=cells[1], email=email),
        )
        if email:
            dev.related.emails.add(email)


def process_slave_device(html: str) -> dict[str, str]:
    """Parses one ``modbus-edit-device`` page into a dict."""
    soup = _soup(html)
    fields = {
        "dev_name": "name",
        "dev_id": "slave_id",
        "dev_ip": "ip",
        "dev_port": "port",
        "dev_cport": "com_port",
        "dev_baud": "baud_rate",
    }
    result = {}
    for elem_id, key in fields.items():
        elem = soup.find(id=elem_id)
        if elem is not None and elem.get("value"):
            result[key] = elem["value"].strip()
    protocol = soup.find(id="dev_protocol")
    if protocol is not None:
        selected = protocol.find("option", selected=True)
        if selected is not None:
            result["protocol"] = selected.get("value", "").strip()
    return result


def process_settings(html: str, dev: DeviceData) -> None:
    """Enabled protocol servers and the runtime hostname."""
    soup = _soup(html)

    hostname = soup.find(id="device_hostname")
    if hostname is not None and hostname.get("value"):
        dev.hostname = hostname["value"].strip()

    settings = {}
    for checkbox_id, (protocol, port_id, transport) in SETTINGS_SERVICES.items():
        checkbox = soup.find(id=checkbox_id)
        port_elem = soup.find(id=port_id)
        if checkbox is None:
            continue
        enabled = checkbox.has_attr("checked")
        port = None
        if port_elem is not None and str(port_elem.get("value", "")).isdigit():
            port = int(port_elem["value"])
        settings[protocol] = {"enabled": enabled, "port": port}
        if enabled and port:
            dev.store(
                "service",
                Service(protocol=protocol, port=port, enabled=True, transport=transport),
            )

    for checkbox_id, key in (
        ("snap7_run", "s7_protocol"),
        ("pstorage_thread", "persistent_storage"),
        ("auto_run", "start_in_run_mode"),
    ):
        checkbox = soup.find(id=checkbox_id)
        if checkbox is not None:
            settings[key] = {"enabled": checkbox.has_attr("checked")}

    if settings.get("s7_protocol", {}).get("enabled"):
        dev.store("service", Service(protocol="s7comm", port=102, enabled=True, transport="tcp"))

    if settings:
        dev.extra["settings"] = settings


def process_hardware(html: str, dev: DeviceData) -> None:
    """Selected hardware layer (I/O driver)."""
    select = _soup(html).find(id="hardware_layer")
    if select is None:
        return
    selected = select.find("option", selected=True)
    if selected is not None:
        dev.extra["hardware_layer"] = selected.get("value", "")
        dev.hardware.id = selected.get_text(strip=True)


def process_monitoring(html: str, dev: DeviceData) -> None:
    """Program variables (located variables) shown on the Monitoring page."""
    for cells, _ in _table_rows(html):
        # Point Name | Type | Location | [Write] | Value
        if len(cells) < 3 or not cells[2].startswith("%"):
            continue
        dev.store("tag", Tag(name=cells[0], type=cells[1], address=cells[2]))


# --- Module Class ---
class OpenPLCv3(DeviceModule):
    """
    PEAT Module for OpenPLC Runtime v3 (the Flask web interface on port 8080).

    Read-only: collects status, programs, users, slave devices, settings,
    hardware layer, monitored variables, and runtime logs.
    """

    device_type = "PLC"
    vendor_id = "OpenPLC"
    vendor_name = "OpenPLC Project"
    module_aliases = ["open", "openplc"]
    default_options = {
        "openplcv3": {
            "username": "",
            "password": "",
            "pull_methods": ["http"],
        },
        "http": {
            "port": 8080,
        },
    }

    @classmethod
    def _base_url(cls, dev: DeviceData) -> str:
        return f"http://{dev.ip}:{dev.options['http']['port']}"

    @classmethod
    def _login(cls, dev: DeviceData) -> requests.Session | None:
        username = dev.options["openplcv3"]["username"]
        password = dev.options["openplcv3"]["password"]
        if not username:
            cls.log.error(
                f"No username configured for {dev.ip}. Set 'openplcv3.username' "
                f"and 'openplcv3.password' in the PEAT config file."
            )
            return None

        session = requests.Session()
        url = f"{cls._base_url(dev)}/login"
        cls.log.info(f"Logging in to {dev.ip} as '{username}'")
        try:
            resp = session.post(
                url,
                data={"username": username, "password": password},
                timeout=10,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as ex:
            cls.log.error(f"Login request to {dev.ip} failed: {ex}")
            return None

        # A successful login redirects to the dashboard,
        # a failed one returns the login page again.
        if resp.status_code in (301, 302, 303) and "login" not in resp.headers.get("Location", ""):
            dev._cache["openplcv3_session"] = session
            return session

        cls.log.error(f"Login failed for {dev.ip} (HTTP {resp.status_code}). Check credentials.")
        return None

    @classmethod
    def _get(cls, dev: DeviceData, session: requests.Session, path: str) -> str | None:
        url = f"{cls._base_url(dev)}/{path}"
        try:
            resp = session.get(url, timeout=15, allow_redirects=False)
        except requests.exceptions.RequestException as ex:
            cls.log.warning(f"GET {url} failed: {ex}")
            return None
        if resp.status_code != 200:
            cls.log.warning(f"GET {url} returned HTTP {resp.status_code}")
            return None
        return resp.text

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        if "http" not in dev.options["openplcv3"]["pull_methods"]:
            cls.log.info("Skipping OpenPLC v3 pull: 'http' not in pull_methods")
            return True

        session = cls._login(dev)
        if session is None:
            return False

        pages = {
            "dashboard": "dashboard",
            "programs": "programs?list_all=1",
            "users": "users",
            "modbus": "modbus",
            "settings": "settings",
            "hardware": "hardware",
            "monitoring": "monitoring",
        }
        processors = {
            "dashboard": process_dashboard,
            "programs": process_programs,
            "users": process_users,
            "settings": process_settings,
            "hardware": process_hardware,
            "monitoring": process_monitoring,
        }

        pulled_any = False
        try:
            for name, path in pages.items():
                html = cls._get(dev, session, path)
                if html is None:
                    continue
                pulled_any = True
                dev.write_file(html, f"{name}.html")
                if name in processors:
                    try:
                        processors[name](html, dev)
                    except Exception as ex:
                        cls.log.warning(f"Failed to parse '{name}' page from {dev.ip}: {ex}")
                if name == "modbus":
                    cls._pull_slave_devices(dev, session, html)

            logs = cls._get(dev, session, "runtime_logs")
            if logs:
                dev.write_file(logs, "openplc_runtime.log")
                dev.store("files", File(name="openplc_runtime.log", description="Runtime Logs"))
        finally:
            try:
                session.get(f"{cls._base_url(dev)}/logout", timeout=5, allow_redirects=False)
            except requests.exceptions.RequestException:
                pass
            session.close()

        if not pulled_any:
            cls.log.error(f"Logged in to {dev.ip} but no pages could be retrieved")
            return False

        dev.description.vendor.name = cls.vendor_name
        dev.os.vendor.name = cls.vendor_name
        dev.os.name = "OpenPLC Runtime v3"
        dev.description.product = "OpenPLC Runtime v3"
        dev.successful_pulls["openplc_http"] = True
        return True

    @classmethod
    def _pull_slave_devices(cls, dev: DeviceData, session: requests.Session, html: str) -> None:
        """Slave (Modbus field) devices the PLC polls. These are other assets on the network."""
        devices = []
        for cells, onclick in _table_rows(html):
            table_id = _table_id(onclick)
            if not table_id:
                continue
            info = {"name": cells[0]}
            if len(cells) >= 6:
                info.update(
                    {
                        "type": cells[1],
                        "di": cells[2],
                        "do": cells[3],
                        "ai": cells[4],
                        "ao": cells[5],
                    }
                )
            page = cls._get(dev, session, f"modbus-edit-device?table_id={table_id}")
            if page:
                info.update(process_slave_device(page))
            if info.get("ip"):
                dev.related.ip.add(info["ip"])
            devices.append(info)

        if devices:
            dev.extra["slave_devices"] = devices
            dev.write_file(devices, "slave_devices.json")

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """Identify OpenPLC v3 by its web login page."""
        url = f"{cls._base_url(dev)}/login"
        try:
            resp = requests.get(url, timeout=5)
        except requests.exceptions.RequestException as ex:
            cls.log.debug(f"Failed to connect to {url}: {ex}")
            return False
        if resp.status_code != 200:
            return False

        release = parse_login_page(resp.text)
        if release is None:
            return False

        cls.log.info(f"Verified OpenPLC Runtime v3 on {dev.ip} (release: {release or 'unknown'})")
        dev.description.vendor.name = cls.vendor_name
        dev.description.product = "OpenPLC Runtime v3"
        dev.os.name = "OpenPLC Runtime v3"
        dev.os.vendor.name = cls.vendor_name
        if release:
            dev.os.version = release
            dev.firmware.version = release
            dev.firmware.release_date = utils.parse_date(release)
        return True


OpenPLCv3.ip_methods = [
    IPMethod(
        name="OpenPLC Runtime v3 web login page",
        description="Checks for the OpenPLC v3 login page over HTTP.",
        type="unicast_ip",
        identify_function=OpenPLCv3._verify_http,
        reliability=8,
        protocol="http",
        transport="tcp",
        default_port=8080,
    ),
]
OpenPLCv3.serial_methods = []

__all__ = ["OpenPLCv3"]
