import pytest

from peat import consts

convert_params = [
    (None, None),
    (True, True),
    (1, 1),
    (2.0, 2.0),
    ("testing123", "testing123"),
    (b"testing123", "testing123"),
    (bytearray("123", "utf-8"), "123"),
    ([b"m340", 6.6], ["m340", 6.6]),
    (Exception(), ""),
    ({}, {}),
    ({"test": 0}, {"test": 0}),
    ({"test": "snek"}, {"test": "snek"}),
    ({"D.Va": b"OP"}, {"D.Va": "OP"}),
    ({"t": [b"m340", 6.6]}, {"t": ["m340", 6.6]}),
]


@pytest.mark.parametrize(("val", "cmp"), convert_params)
def test_convert(val, cmp):
    assert consts.convert(val) == cmp


@pytest.mark.parametrize(("val", "cmp"), convert_params)
def test_convert_idempotent(val, cmp):
    converted = consts.convert(val)
    assert converted == cmp
    assert consts.convert(converted) == cmp
    assert consts.convert(converted) == cmp
    assert consts.convert(consts.convert(converted)) == cmp


def test_get_platform_info():
    info = consts.get_platform_info()
    assert info["hostname"]
    assert info["tcpdump"] is not None
    assert info == consts.SYSINFO


def test_lower_dict():
    assert consts.lower_dict({}) == {}
    assert consts.lower_dict({}, children=False) == {}

    input_data = {"HI": "Hello", "yup": "yO", "sUb_Dict": {"Sub1": "s1", "sUB2": "S2"}}

    assert consts.lower_dict(input_data, children=True) == {
        "hi": "Hello",
        "yup": "yO",
        "sub_dict": {"sub1": "s1", "sub2": "S2"},
    }

    assert consts.lower_dict(input_data, children=False) == {
        "hi": "Hello",
        "yup": "yO",
        "sub_dict": {"Sub1": "s1", "sUB2": "S2"},
    }


def test_str_to_bool():
    with pytest.raises(ValueError):
        consts.str_to_bool("invalidstring")
    assert consts.str_to_bool("false") is False
    assert consts.str_to_bool("true") is True
    assert consts.str_to_bool("TRUE") is True


def test_sanitize_filepath():
    assert consts.sanitize_filepath("") == ""
    assert (
        consts.sanitize_filepath("system/api/1/hardware-info.html")
        == "system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("./system/api/1/hardware-info.html")
        == "system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/hardware-info.html")
        == "/system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/01:01:01-hardware-info.html")
        == "/system/api/1/01_01_01-hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/02:02:02/01:01:01-hardware-info.html")
        == "/system/api/1/02_02_02/01_01_01-hardware-info.html"
    )


def test_sanitize_filename():
    assert consts.sanitize_filename("") == ""
    assert consts.sanitize_filename("hardware-info.html") == "hardware-info.html"
    assert consts.sanitize_filename("01:01:01-hardware-info.html") == "01_01_01-hardware-info.html"


@pytest.mark.parametrize(
    ("release", "version", "expected"),
    [
        ("4.4.0-19041-Microsoft", "#1237-Microsoft Sat Sep 11 14:32:00 PST 2021", True),  # WSL 1
        ("5.15.153.1-microsoft-standard-WSL2", "#1 SMP Fri Mar 29 23:14:13 UTC 2024", True),
        ("6.8.0-45-generic", "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024", False),
    ],
)
def test_is_wsl(mocker, release, version, expected):
    mocker.patch.object(consts, "LINUX", True)
    mocker.patch.object(consts, "_in_container", return_value=False)
    uname = consts.platform.uname_result("Linux", "host", release, version, "x86_64")
    mocker.patch.object(consts.platform, "uname", return_value=uname)
    assert consts._is_wsl() is expected


def test_is_wsl_container(mocker):
    # Docker Desktop and Podman containers on Windows use the WSL 2 kernel
    mocker.patch.object(consts, "LINUX", True)
    mocker.patch.object(consts, "_in_container", return_value=True)
    uname = consts.platform.uname_result(
        "Linux", "host", "5.15.153.1-microsoft-standard-WSL2", "#1 SMP", "x86_64"
    )
    mocker.patch.object(consts.platform, "uname", return_value=uname)
    assert consts._is_wsl() is False


@pytest.mark.parametrize("marker", ["/.dockerenv", "/run/.containerenv"])
def test_in_container(mocker, marker):
    real_exists = consts.os.path.exists
    mocker.patch.object(
        consts.os.path, "exists", side_effect=lambda p: p == marker or real_exists(p)
    )
    assert consts._in_container() is True


def test_is_wsl_not_linux(mocker):
    mocker.patch.object(consts, "LINUX", False)
    assert consts._is_wsl() is False


def test_platform_flags_consistent():
    assert consts.WINDOWS != consts.POSIX
    if consts.WSL:
        assert consts.LINUX
