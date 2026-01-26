import ftplib

import pytest

from peat import CommError, DeviceData
from peat.protocols import FTP


def test_ftp_class():
    with pytest.raises(CommError):
        with FTP("127.0.0.1", 0, 0.01) as obj:
            obj.ftp.quit()
    inst = FTP("127.0.0.1")
    inst.ftp = ftplib.FTP()
    inst.disconnect()
    assert str(inst) == "127.0.0.1"
    assert "127.0.0.1" in repr(inst)


@pytest.mark.parametrize(
    ("welcome", "expected_version"),
    [
        ("220 VxWorks FTP server (VxWorks VxWorks5.5) ready.", "5.5"),
        ("220 VxWorks FTP server (VxWorks 6) ready.", "6"),
        ("220 Wind River FTP server 6.8 ready.", "6.8"),
    ],
)
def test_ftp_process_vxworks_ftp_welcome(welcome, expected_version):
    dev = DeviceData(ip="127.0.0.1")
    inst = FTP("127.0.0.1")

    assert inst.process_vxworks_ftp_welcome(welcome, dev) == expected_version
    assert dev.extra["ftp_welcome"] == welcome
    assert dev.os.version == expected_version
    assert dev.os.name == "VxWorks"
    assert dev.os.vendor.name == "Wind River Systems"
    assert dev.os.vendor.id == "WindRiver"


def test_ftp_process_vxworks_ftp_welcome_bad_arg():
    dev = DeviceData(ip="127.0.0.1")
    inst = FTP("127.0.0.1")

    assert inst.process_vxworks_ftp_welcome("", dev) is None
    assert dev.extra["ftp_welcome"] == ""

    assert inst.process_vxworks_ftp_welcome("bad welcome", dev) is None
    assert dev.extra["ftp_welcome"] == "bad welcome"

    assert inst.process_vxworks_ftp_welcome("") is None
    assert inst.process_vxworks_ftp_welcome("bad welcome") is None
