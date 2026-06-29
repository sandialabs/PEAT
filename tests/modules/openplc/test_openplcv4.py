import pytest
import zipfile
from pathlib import Path
from peat import DeviceData, Event, User, File
from peat.modules.openplc.openplcv4 import OpenPLCv4

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
"""Creates a DeviceData object configured to point to the live Docker container."""
@pytest.fixture
def live_dev(tmp_path):
    dev = DeviceData(ip="127.0.0.1")
    out_dir_path = tmp_path / "devices" / "127.0.0.1"
    out_dir_path.mkdir(parents=True, exist_ok=True)
    dev.__dict__["options"] = {
        "openplcv4": {
            "username": "admin",
            "password": "admin",
            "pull_methods": ["https"],
            "clean_upload": True,
            "plugins_to_query": {}
        },
        "https": {"port": 8443, "ssl": True}
    }
    dev.__dict__["extra"] = {}
    dev.__dict__["successful_pulls"] = {}
    dev.__dict__["_out_dir"] = out_dir_path
    print(type(dev))
    print(dev.__dict__)
    print(dev.__dict__.get("_out_dir"))
    print(dev._out_dir)
    print(hasattr(type(dev), "_out_dir"))
    print(type(dev).__dict__.get("_out_dir"))
    return dev

"""Locates the production Relay_Blink_PLC.zip file."""
@pytest.fixture
def production_plc_zip():
    zip_path = Path("./data_files/Relay_Blink_PLC.zip")
    if not zip_path.exists():
        raise FileNotFoundError(
            f"Expected PLC program zip file not found at: {zip_path.resolve()}.\n"
            "Please ensure the file is committed to your repository in the 'data_files/' directory."
        )
    return zip_path

# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------
"""
Tests SCAN functionality.
Verifies the registered IPMethod can successfully probe and fingerprint
the live Docker container using PEAT's registration schema.
"""
def test_scan_and_fingerprint(live_dev, caplog):
    assert len(OpenPLCv4.ip_methods) > 0, "No IP methods defined on OpenPLCv4 class."
    scan_method = OpenPLCv4.ip_methods[0]
    assert scan_method.name == "openplc_v4_https_api_check"
    result = scan_method.identify_function(live_dev)
    assert result is True, "PEAT scan identity check failed against the live container."
    assert live_dev.os.name == "OpenPLC Runtime v4"
    assert live_dev.description.product == "OpenPLC Runtime v4"
    services = [s for s in live_dev.datastore if s.__class__.__name__ == 'Service']
    assert len(services) > 0
    assert any(s.protocol == "openplc-api" and s.port == 8443 for s in services)

"""
Tests error handling of PUSH.
Verifies that pushing a junk file is rejected and logs a failure.
"""
def test_push_invalid_file(live_dev, tmp_path):
    bad_file = tmp_path / "hello_world.txt"
    bad_file.write_text("hello world")
    result = OpenPLCv4._push(live_dev, bad_file)
    assert result is False, "Pushing a corrupt file should have failed."
    events = [e for e in live_dev.datastore if isinstance(e, Event)]
    assert any(e.action == "file_push" and e.outcome == "failure" for e in events)

"""
Tests successful PUSH.
Pushes a valid program zip
"""
def test_push_valid_file(live_dev, valid_plc_program_zip, caplog):
    result = OpenPLCv4._push(live_dev, production_plc_zip)
    assert result is True, "Failed to push a valid PLC program to the container."
    events = [e for e in live_dev.datastore if isinstance(e, Event)]
    assert any(e.action == "file_push" and e.outcome == "success" for e in events)

"""
Tests PULL functionality on an empty container.
Verifies authentication, parser extraction, database state initialization,
and output file creation in the workspace. Check compile success
"""
def test_pull_and_validate(live_dev, caplog):
    result = OpenPLCv4._pull(live_dev)
    assert result is True, "Failed to run data pull."
    users = [u for u in live_dev.datastore if isinstance(u, User)]
    assert len(users) > 0, "No users were extracted from OpenPLC container."
    assert any(u.name == "admin" for u in users)
    assert (live_dev._out_dir / "openplc_runtime.log").exists()
    assert (live_dev._out_dir / "compilation_status.log").exists()
    # Validate that the compilation status log indicates a compiled/compiling state for test 3
    comp_log = (live_dev._out_dir / "compilation_status.log").read_text()
    assert "Status: " in comp_log
    files = [f for f in live_dev.datastore if isinstance(f, File)]
    assert any(f.name == "openplc_runtime.log" for f in files)
