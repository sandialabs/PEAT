# ruff: noqa: E501  (HTML fixtures mirror real OpenPLC markup)
import pytest

from peat import datastore
from peat.modules.openplc.openplcv3 import (
    OpenPLCv3,
    parse_login_page,
    process_dashboard,
    process_settings,
)

BASE = "http://192.0.2.10:8080"

# Minimal versions of the pages served by the OpenPLC v3 web interface
LOGIN_PAGE = """
<html><head><title>OpenPLC</title></head><body>
<h3>Welcome to OpenPLC</h3>
<form action='login' method='POST' class='login-form'>
  <input type='text' name='username' id='username'/>
  <input type='password' name='password' id='password'/>
  <button>login</button>
</form>
<p>Release: 2025-03-31</p>
</body></html>
"""

DASHBOARD_PAGE = """
<div><h2>Dashboard</h2>
<p style='font-family:'Roboto', sans-serif; font-size:16px'><b>Status: <font color = '#02CC07'>Running</font></b></p>
<p><b>Program:</b> Chemical Reactor</p>
<p><b>Description:</b> </p>
<p><b>File:</b> 326339.st</p>
<p><b>Runtime:</b> 31</p>
</div>
"""

PROGRAMS_PAGE = """
<table>
<tr style='background-color: white'><th>Program Name</th><th>File</th><th>Date Uploaded</th></tr>
<tr onclick="document.location='reload-program?table_id=38'"><td>Chemical Reactor</td><td>326339.st</td><td>Jan 15, 2026 - 04:14PM</td></tr>
</table>
"""

USERS_PAGE = """
<table>
<tr style='background-color: white'><th>Full Name</th><th>Username</th><th>Email</th></tr>
<tr onclick="document.location='edit-user?table_id=10'"><td>OpenPLC User</td><td>openplc</td><td>openplc@openplc.com</td></tr>
</table>
"""

MODBUS_PAGE = """
<table>
<tr style='background-color: white'><th>Device Name</th><th>Device Type</th><th>DI</th><th>DO</th><th>AI</th><th>AO</th></tr>
<tr onclick="document.location='modbus-edit-device?table_id=1'"><td>Feed 1</td><td>TCP</td><td>-</td><td>-</td><td>%IW100 to %IW101</td><td>%QW100 to %QW100</td></tr>
</table>
"""

MODBUS_DEVICE_PAGE = """
<input type='text' id='dev_name' value='Feed 1'>
<select id='dev_protocol'><option value='Uno'>Uno</option><option selected='selected' value='TCP'>TCP</option></select>
<input type='text' id='dev_id' value='247'>
<input type='text' id='dev_ip' value='192.168.95.10'>
<input type='text' id='dev_port' value='502'>
"""

SETTINGS_PAGE = """
<input type='text' id='device_hostname' name='device_hostname' value='plc'>
<input id='modbus_server' type='checkbox' checked>
<input type='text' id='modbus_server_port' value='502'>
<input id='snap7_run' type='checkbox'>
<input id='dnp3_server' type='checkbox'>
<input type='text' id='dnp3_server_port' value='20000'>
<input id='enip_server' type='checkbox'>
<input type='text' id='enip_server_port' value='44818'>
<input id='auto_run' type='checkbox' checked>
"""

HARDWARE_PAGE = """
<select id='hardware_layer'>
<option value='blank'>Blank</option>
<option selected='selected' value='blank_linux'>Blank Linux</option>
</select>
"""

MONITORING_PAGE = """
<table>
<tr><th>Point Name</th><th>Type</th><th>Location</th><th>Value</th></tr>
<tr onclick="document.location='point-info?table_id=0'"><td>pressure</td><td>UINT</td><td>%IW108</td><td>0</td></tr>
<tr onclick="document.location='point-info?table_id=1'"><td>run_bit</td><td>BOOL</td><td>%QX5.0</td><td>TRUE</td></tr>
</table>
"""


@pytest.fixture
def dev(mocker):
    mocker.patch.object(datastore, "objects", [])
    dev = datastore.get("192.0.2.10")
    dev._runtime_options["openplcv3"] = {"username": "openplc", "password": "openplc"}
    dev._runtime_options["http"] = {"port": 8080}
    return dev


def test_parse_login_page():
    assert parse_login_page(LOGIN_PAGE) == "2025-03-31"
    assert parse_login_page("<html>Some other web server</html>") is None
    # OpenPLC v4 or other pages that mention OpenPLC without a login form
    assert parse_login_page("<html>OpenPLC docs</html>") is None


def test_verify_http(dev, requests_mock):
    requests_mock.get(f"{BASE}/login", text=LOGIN_PAGE)
    assert OpenPLCv3._verify_http(dev) is True
    assert dev.os.name == "OpenPLC Runtime v3"
    assert dev.os.version == "2025-03-31"


def test_verify_http_not_openplc(dev, requests_mock):
    requests_mock.get(f"{BASE}/login", text="<html>nginx</html>")
    assert OpenPLCv3._verify_http(dev) is False


def test_process_dashboard(dev):
    process_dashboard(DASHBOARD_PAGE, dev)
    assert dev.run_mode == "RUNNING"
    assert dev.logic.name == "Chemical Reactor"
    assert dev.logic.file.name == "326339.st"


def test_process_settings(dev):
    process_settings(SETTINGS_PAGE, dev)
    assert dev.hostname == "plc"
    assert dev.extra["settings"]["modbus_tcp"] == {"enabled": True, "port": 502}
    assert dev.extra["settings"]["dnp3"]["enabled"] is False
    assert [s.protocol for s in dev.service] == ["modbus_tcp"]


def test_pull(dev, requests_mock, tmp_path):
    dev._out_dir = tmp_path
    requests_mock.post(f"{BASE}/login", status_code=302, headers={"Location": "/dashboard"})
    requests_mock.get(f"{BASE}/dashboard", text=DASHBOARD_PAGE)
    requests_mock.get(f"{BASE}/programs?list_all=1", text=PROGRAMS_PAGE)
    requests_mock.get(f"{BASE}/users", text=USERS_PAGE)
    requests_mock.get(f"{BASE}/modbus", text=MODBUS_PAGE)
    requests_mock.get(f"{BASE}/modbus-edit-device?table_id=1", text=MODBUS_DEVICE_PAGE)
    requests_mock.get(f"{BASE}/settings", text=SETTINGS_PAGE)
    requests_mock.get(f"{BASE}/hardware", text=HARDWARE_PAGE)
    requests_mock.get(f"{BASE}/monitoring", text=MONITORING_PAGE)
    requests_mock.get(f"{BASE}/runtime_logs", text="OpenPLC Runtime starting...\n")
    requests_mock.get(f"{BASE}/logout", status_code=302, headers={"Location": "/login"})

    assert OpenPLCv3._pull(dev) is True

    # Read-only: the only non-GET request is the login
    methods = {(r.method, r.path) for r in requests_mock.request_history}
    assert {m for m, _ in methods} == {"GET", "POST"}
    assert [p for m, p in methods if m == "POST"] == ["/login"]

    assert dev.run_mode == "RUNNING"
    assert dev.logic.name == "Chemical Reactor"
    assert dev.extra["programs"][0]["file"] == "326339.st"
    assert dev.users[0].name == "openplc"
    assert dev.extra["slave_devices"][0]["ip"] == "192.168.95.10"
    assert "192.168.95.10" in dev.related.ip
    assert dev.extra["hardware_layer"] == "blank_linux"
    assert {t.name for t in dev.tag} == {"pressure", "run_bit"}
    assert (tmp_path / "openplc_runtime.log").exists()
    assert (tmp_path / "slave_devices.json").exists()


def test_pull_bad_credentials(dev, requests_mock):
    requests_mock.post(f"{BASE}/login", text=LOGIN_PAGE)  # login page again = failure
    assert OpenPLCv3._pull(dev) is False
