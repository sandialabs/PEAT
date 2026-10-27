"""
Integration tests against a live SCEPTRE bennu field device VM.

The VM is started with ``scripts/run-bennu-vm.sh``, loaded with
``data_files/ep/dnp3-server.xml``. Set ``BENNU_FTP_PORT`` if FTP
isn't forwarded to the default port of 2121.
"""

import os

import pytest

from peat import SCEPTRE, config, datastore

pytestmark = pytest.mark.container

FTP_PORT = int(os.environ.get("BENNU_FTP_PORT", "2121"))
CONFIG_FILE = "ep/dnp3-server.xml"


@pytest.fixture
def live_dev(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp_results"},
    )
    mocker.patch.object(datastore, "objects", [])
    dev = datastore.get("127.0.0.1")
    dev._runtime_options["ftp"] = {"port": FTP_PORT}
    return dev


def test_verify_ftp(live_dev):
    assert SCEPTRE._verify_ftp(live_dev) is True
    assert "vsFTPd" in live_dev.extra["ftp_welcome"]
    assert {"bennu-field-deviced", "config.xml"} <= live_dev.related.files
    assert any(s.protocol == "ftp" and s.status == "verified" for s in live_dev.service)


def test_pull(live_dev, datapath, mocker):
    assert SCEPTRE.pull(live_dev) is True

    # Firmware is a copy of the running bennu-field-deviced binary
    assert live_dev.firmware.original.startswith(b"\x7fELF")
    assert live_dev.firmware.file.name == "bennu-field-deviced"
    assert live_dev.firmware.file.local_path.read_bytes() == live_dev.firmware.original
    assert live_dev.firmware.hash.sha256

    # Config pulled from the device is the one loaded into it
    config_path = live_dev._out_dir / "ftp_files" / "config.xml"
    assert config_path.read_bytes() == datapath(CONFIG_FILE).read_bytes()

    # Data parsed from the device matches parsing the same file locally
    mocker.patch.object(datastore, "objects", [])
    local = SCEPTRE.parse(datapath(CONFIG_FILE))
    assert live_dev.name == local.name == "rtu-1"
    assert live_dev.type == "RTU"
    for field in ["tag", "registers", "io"]:
        pulled = [m.dict(exclude_defaults=True) for m in getattr(live_dev, field)]
        parsed = [m.dict(exclude_defaults=True) for m in getattr(local, field)]
        assert pulled == parsed, field
    assert live_dev.logic.original == local.logic.original
    assert "rtu-1-dnp3-outstation.log" in live_dev.related.files
