"""
Integration tests against a live SCEPTRE bennu field device VM.

The VM is started with ``scripts/run-bennu-vm.sh``, loaded with
``data_files/ep/dnp3-server.xml``. Set ``BENNU_FTP_PORT`` if FTP
isn't forwarded to the default port of 2121. Set ``BENNU_SERIAL_LOG``
to the VM's serial log to check that bennu-watcherd installs pushed firmware.

Tests can run in any order (pytest-randomly). Pushing firmware leaves a valid
``bennu-field-deviced.firmware`` on the VM, which is pulled after that.
"""

import os
import time
from pathlib import Path

import pytest

from peat import SCEPTRE, config, datastore
from peat.modules.sandia.sceptre_fcd import FIRMWARE_PREFIX, FIRMWARE_UPLOAD_NAME

pytestmark = pytest.mark.container

FTP_PORT = int(os.environ.get("BENNU_FTP_PORT", "2121"))
SERIAL_LOG = os.environ.get("BENNU_SERIAL_LOG")
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
    assert live_dev.firmware.file.name in (FIRMWARE_UPLOAD_NAME, FIRMWARE_PREFIX)
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


def _watcher_log_count(message: str) -> int:
    if not SERIAL_LOG or not Path(SERIAL_LOG).is_file():
        return 0
    return Path(SERIAL_LOG).read_text(errors="replace").count(message)


def test_push_config_unsupported(live_dev):
    assert SCEPTRE.push(live_dev, b"<SCEPTRE/>", "config") is False


def test_push_firmware(live_dev):
    original, _, _ = SCEPTRE._download_ftp(live_dev, [FIRMWARE_PREFIX], save=False)
    assert original.startswith(b"\x7fELF")
    before, _, _ = SCEPTRE._download_ftp(live_dev, [FIRMWARE_UPLOAD_NAME], save=False)
    restarts = _watcher_log_count("field-device restarted")

    # Not one of the hashes bennu-watcherd accepts, so it isn't uploaded
    assert SCEPTRE.push(live_dev, b"not a bennu firmware", "firmware") is False
    after, _, _ = SCEPTRE._download_ftp(live_dev, [FIRMWARE_UPLOAD_NAME], save=False)
    assert after == before

    # The original binary is accepted
    assert SCEPTRE.push(live_dev, original, "firmware") is True
    assert FIRMWARE_UPLOAD_NAME in live_dev.related.files
    assert live_dev.event[-1].action == "file_push"
    assert live_dev.event[-1].outcome == "success"

    # The pushed firmware is the one pulled now
    assert SCEPTRE.pull_firmware(live_dev) == original
    assert live_dev.firmware.file.name == FIRMWARE_UPLOAD_NAME

    # The watcher only installs firmware that differs from the last one it installed
    if SERIAL_LOG and before != original:
        for _ in range(30):
            if _watcher_log_count("field-device restarted") > restarts:
                break
            time.sleep(1)
        assert _watcher_log_count("field-device restarted") > restarts
