import json
import sys
from datetime import datetime
from pathlib import Path
from platform import python_version

import pytest

from peat import config, utils


def test_convert_to_snake_case():
    assert utils.convert_to_snake_case("CamelCase") == "camel_case"
    assert utils.convert_to_snake_case("snake_case") == "snake_case"


def test_clean_replace():
    assert utils.clean_replace(" some$bad$@string", " ", "@$") == "some bad  string"


def test_fmt_duration():
    assert utils.fmt_duration(0) == "0 seconds"
    assert utils.fmt_duration(59) == "59 seconds"
    assert utils.fmt_duration(60) == "1 minute [60.00 seconds]"
    assert utils.fmt_duration(120) == "2 minutes [120.00 seconds]"


def test_fmt_size():
    assert utils.fmt_size(0) == "0 bytes [0 bytes]"
    assert utils.fmt_size(1024) == "1.02 KB [1024 bytes]"


def test_sort():
    assert utils.sort({"5": 1, "4": 1, "3": 1}) == {"3": 1, "4": 1, "5": 1}


def test_move_item():
    obj = ["x", "y", "z"]
    utils.move_item(obj, 1, "z")
    assert obj == ["x", "z", "y"]


def test_move_file(tmp_path):
    t_dir = tmp_path / "test_move_file_dir"
    t_dir.mkdir(exist_ok=True, parents=True)
    t_src = tmp_path / "test_move_file_file.txt"
    t_src.write_text("some data")

    assert t_src.is_file()
    assert t_dir.is_dir()

    res = utils.move_file(t_src, t_dir)
    assert not t_src.is_file()
    assert res == Path(t_dir, t_src.name)
    assert res.is_file()

    t_src.write_text("some data")
    res = utils.move_file(t_src, t_dir)

    assert res == Path(t_dir, f"{t_src.name}.1")
    assert res.is_file()


def test_merge():
    with pytest.raises(ValueError):
        utils.merge(None, None)

    assert utils.merge(None, {"d2": 2}) == {"d2": 2}
    assert utils.merge({"d1": 1}, None) == {"d1": 1}
    assert utils.merge({"d1": 1}, {"d2": 2}) == {"d1": 1, "d2": 2}


def test_parse_date():
    data = "nov 1 2019 12:26:51"
    iso_expected = "2019-11-01T12:26:51"
    datetime_expected = datetime(2019, 11, 1, 12, 26, 51)

    assert utils.parse_date(data) == datetime_expected
    assert utils.parse_date(data).isoformat() == iso_expected
    assert utils.parse_date(iso_expected).isoformat() == iso_expected
    assert utils.parse_date(iso_expected) == datetime_expected
    assert utils.parse_date(b"nov 1 2019 12:26:51") == datetime_expected  # type: ignore
    assert not utils.parse_date("")
    assert not utils.parse_date(b"")
    assert not utils.parse_date(None)


def test_get_formatted_platform_str():
    assert python_version() in utils.get_formatted_platform_str()


def test_get_debug_string():
    assert utils.get_debug_string() != ""


def test_get_resource():
    with pytest.raises(FileNotFoundError):
        utils.get_resource("peat", "TESTINGDOESNOTEXIST")
    with pytest.raises(ValueError):
        utils.get_resource("", "TESTINGDOESNOTEXIST")
    with pytest.raises(ModuleNotFoundError):
        utils.get_resource("TESTINGDOESNOTEXIST", "TESTINGDOESNOTEXIST")
    assert utils.get_resource("peat.parsing.plc_open.core_modules", "iec_std.csv")


def test_check_file(mocker, datapath):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    assert utils.check_file(".") == Path(".").resolve()

    dpth = datapath("dummy_text_file.txt")
    assert utils.check_file(dpth) == dpth
    assert utils.check_file(dpth, ext=".txt") == dpth
    assert utils.check_file(dpth, ext=[".txt"]) == dpth
    assert utils.check_file(dpth, ext="nope") == dpth
    assert utils.check_file("-") == "-"

    if hasattr(sys.stdin, "isatty"):
        mocker.patch("sys.stdin.isatty", return_value=True)
        assert utils.check_file("-") is None
        assert utils.check_file(None) is None


def test_file_perms_to_octal():
    assert not utils.file_perms_to_octal("")
    assert not utils.file_perms_to_octal("rwx")
    assert utils.file_perms_to_octal("rwxrwxr--") == "0774"
    assert utils.file_perms_to_octal("r--r--r--") == "0444"
    assert utils.file_perms_to_octal("rw------x") == "0601"


def test_write_temp_file_none_ext(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": None})
    assert utils.write_temp_file({}, "") is None

    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})
    pth = utils.write_temp_file("data", "test-ext-label.test")
    assert pth.is_file()
    assert "test-ext-label" in pth.name
    assert pth.suffix == ".test"


def test_write_file_general(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "OUT_DIR": tmp_path,
            "RUN_DIR": tmp_path,
        },
    )
    file = tmp_path / "pathtest12345"
    text = "write_file_path12345 1.0"

    assert utils.write_file(text, file) is True
    assert file.is_file()
    assert file.read_text(encoding="utf-8") == text
    assert utils.write_file(None, None) is False


def test_write_file_str_path(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "OUT_DIR": tmp_path,
            "RUN_DIR": tmp_path,
        },
    )
    file_name = "strpathtest12345"
    pth = tmp_path / file_name

    assert utils.write_file("teststring", file_name) is False
    assert not pth.is_file()


def test_write_file_json(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})
    file = tmp_path / "jsontest12345"

    assert utils.write_file({}, file) is True

    assert file.is_file()
    assert file.read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize(
    ("invalid_name", "valid_name"),
    [
        ("CON", "CON_"),
        ("some_file?i=1.html", "some_file_i=1.html"),
    ],
)
def test_write_file_filename_validation(tmp_path, mocker, invalid_name, valid_name):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    invalid_path = tmp_path / invalid_name
    valid_path = tmp_path / valid_name
    test_string = f"testing123+{invalid_name}+{valid_name}"

    assert utils.write_file(test_string, invalid_path) is True

    assert not invalid_path.is_file()
    assert valid_path.is_file()
    assert valid_path.read_text(encoding="utf-8") == test_string


def test_write_file_merge_existing(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    test_path = tmp_path / "test_dict.json"
    test_dict = {1: "one", "two": 2}
    assert utils.write_file(data=test_dict, file=test_path)
    assert utils.write_file(data={3: "three"}, file=test_path, merge_existing=True)
    assert json.loads(test_path.read_text(encoding="utf-8")) == {
        "1": "one",
        "two": 2,
        "3": "three",
    }

    assert utils.write_file(data={4: "four"}, file=test_path, merge_existing=False)
    assert json.loads(test_path.read_text(encoding="utf-8")) == {
        "1": "one",
        "two": 2,
        "3": "three",
    }

    # TODO: expand this test to cover all possible cases for merge_existing


filehash_compares = [
    ("md5", "7F2ABABA423061C509F4923DD04B6CF1"),
    ("sha1", "4C0D2B951FFABD6F9A10489DC40FC356EC1D26D5"),
    ("sha256", "B822F1CD2DCFC685B47E83E3980289FD5D8E3FF3A82DEF24D7D1D68BB272EB32"),
    (
        "sha512",
        "4120117B3190BA5E24044732B0B09AA9ED50EB1567705ABCBFA78431A4E0A96B1152ED7F4925966B1C82325E186A8100E692E6D2FCB6702572765820D25C7E9E",
    ),
]


@pytest.mark.parametrize(("algo", "cmp"), filehash_compares)
def test_calc_hash(datapath, algo, cmp):
    assert utils.calc_hash(datapath("hashtest.txt"), algo) == cmp


def test_gen_hashes_path(datapath):
    """Operate on the file path (Path input)."""
    f_result = utils.gen_hashes(datapath("hashtest.txt"))

    assert f_result["md5"] == filehash_compares[0][1]
    assert f_result["sha1"] == filehash_compares[1][1]
    assert f_result["sha256"] == filehash_compares[2][1]
    assert f_result["sha512"] == filehash_compares[3][1]


def test_gen_hashes_text(text_data):
    """Operating on raw text data (str input)."""
    t_result = utils.gen_hashes(text_data("hashtest.txt"))

    assert t_result["md5"] == filehash_compares[0][1]
    assert t_result["sha1"] == filehash_compares[1][1]
    assert t_result["sha256"] == filehash_compares[2][1]
    assert t_result["sha512"] == filehash_compares[3][1]


def test_utc_now():
    """
    Not really a comprehensive test, but ensures it's timezone-aware and UTC.
    """
    assert str(utils.utc_now().tzinfo) == "UTC"


def test_time_now():
    assert utils.time_now()
    assert isinstance(utils.time_now(), str)


def test_deep_get():
    data = {"1": {"2": {"3": "hi"}}}

    assert utils.deep_get(data, "1.2.3") == "hi"
    assert utils.deep_get(data, "1")
    assert not utils.deep_get(data, "1.2.3.4")
    assert not utils.deep_get(data, "1.2.3.hi")
    assert not utils.deep_get(data, "")


def test_is_ip_address():
    assert utils.is_ip("192.168.0.1")
    assert utils.is_ip("fe80::457f:9ce8:afa1:2118")

    assert not utils.is_ip("")
    assert not utils.is_ip("fe80:::")
    assert not utils.is_ip("192.168.")
    assert not utils.is_ip("192.168.168.168.168")


def test_is_email():
    assert utils.is_email("example@example.com")

    assert not utils.is_email("")
    assert not utils.is_email("google.com")


def test_is_mac():
    assert utils.is_mac("00:00:00:00:00:00")
    assert utils.is_mac("00:A0:A9:A8:12:A1")
    assert utils.is_mac("00:b0:b9:08:12:01")

    assert not utils.is_mac("")
    assert not utils.is_mac("01:02:03:04:05:0")
