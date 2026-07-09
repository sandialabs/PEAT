from pathlib import Path

import pytest

from peat import datastore
from peat.modules.openplc.openplcv4 import OpenPLCv4

# -----------------------------------------------------------------------------
# Module-level Marker
# -----------------------------------------------------------------------------
# This marks every test case in this file as a 'live' test, meaning they will
# be skipped by default in local runs and the core CI suite.
pytestmark = pytest.mark.live


# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
@pytest.fixture
def live_dev(mocker):
    """Creates a DeviceData object configured to point to the live Docker container."""
    mocker.patch.object(datastore, "objects", [])
    dev = datastore.get("127.0.0.1")
    dev._runtime_options["openplcv4"] = {"username": "admin", "password": "admin"}
    return dev


@pytest.fixture
def production_plc_zip():
    """Locates the production Relay_Blink_PLC.zip file."""
    zip_path = Path("tests/modules/openplc/data_files/Relay_Blink_PLC.zip")
    if not zip_path.exists():
        raise FileNotFoundError(
            f"Expected PLC program zip file not found at: {zip_path.resolve()}.\n"
            "Please ensure the file is committed to your repository in the \
                'data_files/' directory."
        )
    return zip_path


# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------
def test_scan_and_fingerprint(live_dev):
    """
    Tests SCAN functionality.
    Verifies the registered IPMethod can successfully probe and fingerprint
    the live Docker container using PEAT's registration schema.
    """
    scan_method = next(
        m for m in OpenPLCv4.ip_methods if m.name == "OpenPLC Runtime v4 HTTPS REST API"
    )
    result = scan_method.identify_function(live_dev)
    assert result is True, "PEAT scan identity check failed."
    assert live_dev.os.name == "OpenPLC Runtime v4"
    assert any(s.protocol == "openplc_api" and s.port == 8443 for s in live_dev.service)


def test_push_valid_file(live_dev, production_plc_zip):
    """
    Tests successful PUSH.
    Pushes a valid program zip
    """
    result = OpenPLCv4._push(live_dev, production_plc_zip, "")
    assert result is True, "Failed to push a valid PLC program."
    assert any(e.action == "file_push" and e.outcome == "success" for e in live_dev.event)


def test_pull_and_validate(live_dev):
    """
    Tests PULL functionality on an empty container.
    Verifies authentication, parser extraction, database state initialization,
    and output file creation in the workspace. Check compile success
    """
    result = OpenPLCv4._pull(live_dev)
    assert result is True, "Failed to run data pull."
    assert len(live_dev.users) > 0, "No users were extracted from OpenPLC container."
    assert any(u.name == "admin" for u in live_dev.users)
    assert (live_dev._out_dir / "openplc_runtime.log").exists()
    assert (live_dev._out_dir / "compilation_status.log").exists()
    # Validate that the compilation status log indicates a compiled/compiling state for test 3
    comp_log = (live_dev._out_dir / "compilation_status.log").read_text()
    assert "Status: " in comp_log
    assert any(f.name == "openplc_runtime.log" for f in live_dev.files)
