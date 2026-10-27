import hashlib

import pytest

from peat import SCEPTRE, datastore
from peat.modules.sandia.sceptre_fcd import FIRMWARE_UPLOAD_NAME, accepted_firmware_hashes

ORIGINAL = b"\x7fELF bennu _SHELL_0 SHELL_0"
SHELL = ORIGINAL.replace(b"_SHELL_0", b"_SHELL_1")


@pytest.fixture
def dev(mocker):
    mocker.patch.object(datastore, "objects", [])
    return datastore.get("192.0.2.10")


def test_accepted_firmware_hashes():
    assert accepted_firmware_hashes(ORIGINAL) == {
        hashlib.sha256(ORIGINAL).hexdigest(),
        hashlib.sha256(b"\x7fELF bennu _SHELL_1 SHELL_0").hexdigest(),
        hashlib.sha256(b"\x7fELF bennu _SHELL_1 SHELL_1").hexdigest(),
    }


def test_push_config_unsupported(dev, mocker):
    upload = mocker.patch.object(SCEPTRE, "_upload_ftp")
    assert SCEPTRE.push(dev, b"<SCEPTRE/>", "config") is False
    upload.assert_not_called()


@pytest.mark.parametrize("firmware", [ORIGINAL, ORIGINAL.replace(b"SHELL_0", b"SHELL_1")])
def test_push_firmware(dev, mocker, firmware):
    mocker.patch.object(SCEPTRE, "_download_ftp", return_value=(ORIGINAL, None, "x"))
    upload = mocker.patch.object(SCEPTRE, "_upload_ftp", return_value=True)

    assert SCEPTRE.push(dev, firmware, "firmware") is True

    upload.assert_called_once_with(dev, FIRMWARE_UPLOAD_NAME, firmware)
    assert dev.event[-1].action == "file_push"
    assert dev.event[-1].outcome == "success"


def test_push_firmware_rejected(dev, mocker):
    # bennu-watcherd ignores firmware that doesn't match the accepted hashes
    mocker.patch.object(SCEPTRE, "_download_ftp", return_value=(ORIGINAL, None, "x"))
    upload = mocker.patch.object(SCEPTRE, "_upload_ftp", return_value=True)
    assert SCEPTRE.push(dev, b"not bennu", "firmware") is False
    upload.assert_not_called()


def test_push_firmware_unreadable(dev, mocker, tmp_path):
    upload = mocker.patch.object(SCEPTRE, "_upload_ftp")
    assert SCEPTRE._push(dev, tmp_path, "firmware") is False
    upload.assert_not_called()


@pytest.mark.parametrize(
    ("uploaded", "original", "expected"),
    [
        # Accepted upload is installed
        (SHELL, ORIGINAL, SHELL),
        # Rejected upload is ignored by the watcher, the original is running
        (b"not bennu", ORIGINAL, ORIGINAL),
        # Nothing uploaded yet
        (None, ORIGINAL, ORIGINAL),
        # No original to check against
        (SHELL, None, SHELL),
    ],
)
def test_pull_firmware(dev, mocker, uploaded, original, expected):
    def download(_dev, candidates, *_args, **_kwargs):
        data = uploaded if candidates == [FIRMWARE_UPLOAD_NAME] else original
        return (data, None, candidates[0]) if data is not None else (None, None, "")

    mocker.patch.object(SCEPTRE, "_download_ftp", side_effect=download)
    assert SCEPTRE.pull_firmware(dev) == expected


def test_push_firmware_upload_failed(dev, mocker):
    mocker.patch.object(SCEPTRE, "_download_ftp", return_value=(None, None, ""))
    mocker.patch.object(SCEPTRE, "_upload_ftp", return_value=False)
    assert SCEPTRE.push(dev, ORIGINAL, "firmware") is False
    assert dev.event[-1].outcome == "failure"


def test_upload_ftp_bad_type(dev):
    assert SCEPTRE._upload_ftp(dev, "x", 123) is False
