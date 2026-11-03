"""
Tests for parsing Woodward ToolKit and Control Assistant files through the
easYgen and 2301E device modules, including the ``peat parse`` CLI.
"""

import gzip
import json
import sys
from pathlib import Path
from subprocess import run
from typing import Final

import pytest

from peat import config, datastore
from peat.modules.woodward import WDW2301E, Easygen3500XT
from peat.modules.woodward.easygen_3500xt import WOODWARD_FILE_PARSERS, identify_woodward_file
from peat.modules.woodward.wdw_tc import tc_head_application_info

from .nrbf_builder import (
    build_generic_wset,
    build_sid_file,
    build_sid_xml,
    build_woodward_wset,
    build_woodward_wtool,
)

REAL_WSET_GZ: Final[Path] = Path(
    "devices", "woodward", "easygen-3500", "4_MVA_Diesel_20161116.wset.gz"
)
TC_FIXTURE: Final[str] = "tunables_synthetic.tc"
#: Application identifier of the synthetic .tc file, which isn't a known application
TC_FIXTURE_APPLICATION: Final[str] = "5418-1234 NEW"
#: Application identifier of the easYgen-3500 (see toolkit.TOOLKIT_APPLICATIONS)
EASYGEN_APPLICATION: Final[str] = "5418-6722 NEW"


@pytest.fixture
def run_dirs(mocker, tmp_path):
    """Point PEAT's output directories at a temporary directory."""
    device_dir = tmp_path / "device_results"
    temp_dir = tmp_path / "temp_results"
    device_dir.mkdir()
    temp_dir.mkdir()
    mocker.patch.dict(
        config["CONFIG"],
        {"RUN_DIR": tmp_path, "DEVICE_DIR": device_dir, "TEMP_DIR": temp_dir},
    )
    # Prevent devices from other tests leaking into this one
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


@pytest.fixture
def fixtures(tmp_path, datapath, examples_dir) -> dict[str, Path]:
    """Copies of each file type in a scratch directory."""
    sources = {
        "wset": (
            REAL_WSET_GZ.with_suffix("").name,
            lambda: gzip.decompress((examples_dir / REAL_WSET_GZ).read_bytes()),
        ),
        "synthetic.wset": ("synthetic_settings.wset", build_woodward_wset),
        "sid": ("EG3200XTP1 2.12-0_50976.sid", build_sid_file),
        "xml.sid": ("EG3200XTP1 2.12-0_50976.CAN.sid", build_sid_xml),
        "wtool": ("synthetic_tool.wtool", build_woodward_wtool),
        "tc": (TC_FIXTURE, datapath(TC_FIXTURE).read_bytes),
        # The synthetic tunables with the application identifier of an easYgen
        "easygen.tc": (
            "easygen_tunables.tc",
            lambda: (
                datapath(TC_FIXTURE)
                .read_bytes()
                .replace(TC_FIXTURE_APPLICATION.encode(), EASYGEN_APPLICATION.encode())
            ),
        ),
    }
    scratch = tmp_path / "input"
    scratch.mkdir()
    paths = {}
    for key, (name, build) in sources.items():
        path = scratch / name
        path.write_bytes(build())
        paths[key] = path
    return paths


def test_module_attributes():
    # .tc files are claimed by file signature only, depending on the application
    assert Easygen3500XT.filename_patterns == ["*.wset", "*.sid", "*.wtool"]
    assert [s.default_filename for s in Easygen3500XT.file_signatures] == [
        "settings.wset",
        "application.sid",
        "tool.wtool",
        "tunables.tc",
    ]
    assert "easygen" in Easygen3500XT.module_aliases
    assert "easYgen-3500XT-P1" in Easygen3500XT.supported_models
    assert "easYgen-3200" in Easygen3500XT.supported_models
    assert set(WOODWARD_FILE_PARSERS) == {"wset", "sid", "wtool", "tc"}
    assert WDW2301E.filename_patterns == []
    assert [s.default_filename for s in WDW2301E.file_signatures] == ["tunables.tc"]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("wset", "wset"),
        ("synthetic.wset", "wset"),
        ("sid", "sid"),
        ("xml.sid", "sid"),
        ("wtool", "wtool"),
        ("tc", "tc"),
        ("easygen.tc", "tc"),
    ],
)
def test_identify_woodward_file(fixtures, key, expected):
    data = fixtures[key].read_bytes()
    assert identify_woodward_file(data, fixtures[key].suffix) == expected
    # Content wins over the extension
    assert identify_woodward_file(data, ".bin") == expected
    assert identify_woodward_file(data, "") == expected


def test_identify_woodward_file_fallbacks():
    assert identify_woodward_file(b"unknown content", ".wset") == "wset"
    assert identify_woodward_file(b"unknown content", "tc") == "tc"
    assert identify_woodward_file(b"unknown content", ".txt") is None
    assert identify_woodward_file(b"", "") is None
    # A .NET stream without the ToolKit header is still treated as a settings file
    assert identify_woodward_file(build_generic_wset(header=b"\x00" * 10), "") == "wset"


def test_file_signatures_match_only_their_type(fixtures):
    signatures = {s.default_filename: s for s in Easygen3500XT.file_signatures}
    expected = {
        "wset": "settings.wset",
        "synthetic.wset": "settings.wset",
        "sid": "application.sid",
        "xml.sid": "application.sid",
        "wtool": "tool.wtool",
        "easygen.tc": "tunables.tc",
    }
    for key, path in fixtures.items():
        matches = [name for name, sig in signatures.items() if sig.matches(path)]
        assert matches == ([expected[key]] if key in expected else []), key
    # Tunable files of other controls are left to the 2301E module
    wdw_signature = WDW2301E.file_signatures[0]
    assert [key for key, path in fixtures.items() if wdw_signature.matches(path)] == ["tc"]


def test_tc_head_application_info(fixtures):
    data = fixtures["easygen.tc"].read_bytes()
    assert tc_head_application_info(data)["model"] == "3500"
    # Only the start of the file is needed, a cut off line is ignored
    assert tc_head_application_info(data[:200])["model"] == "3500"
    app = tc_head_application_info(fixtures["tc"].read_bytes())
    assert app["id"] == TC_FIXTURE_APPLICATION
    assert not app["model"]
    assert tc_head_application_info(fixtures["synthetic.wset"].read_bytes()) is None
    assert tc_head_application_info(b"") is None


@pytest.mark.usefixtures("run_dirs")
def test_parse_real_wset(fixtures, assert_glob_path):
    dev = Easygen3500XT.parse(fixtures["wset"])
    assert dev is not None
    assert dev.get_id() == "4_MVA_Diesel_20161116"
    assert dev.description.vendor.name == "Woodward, Inc"
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3500"
    assert dev.description.product == "easYgen-3500"
    assert dev.type == "Genset Controller"
    assert dev.firmware.id == "5418-6722-NEW"
    assert dev.extra["wset"]["num_parameters"] == 2756
    assert dev.extra["parameters"]["Config_Admin.1702 Device number"] == 1
    out_dir = dev.get_out_dir()
    parsed_file = assert_glob_path(out_dir, "parsed-wset.json")
    parsed = json.loads(parsed_file.read_text(encoding="utf-8"))
    assert parsed["num_parameters"] == 2756
    assert_glob_path(out_dir, "4_MVA_Diesel_20161116.wset")
    assert_glob_path(out_dir, "device-data-summary.json")
    assert dev in datastore.objects
    # Data model and logic
    assert len(dev.registers) == 4548
    assert len(dev.tag) == 919
    assert len(dev.io) == 112
    assert sorted(i.name for i in dev.interface) == [
        "CAN 1",
        "CAN 2",
        "CAN 3",
        "Serial 1",
        "Serial 2",
    ]
    assert dev.logic.file.local_path == fixtures["wset"]
    assert dev.logic.name == "easYgen-3500 LogicsManager"
    logic_file = assert_glob_path(out_dir, "logic.st")
    assert logic_file.read_text(encoding="utf-8").startswith("PROGRAM main")
    tc6_file = assert_glob_path(out_dir, "logic-tc6.xml")
    assert "plcopen.org" in tc6_file.read_text(encoding="utf-8")


@pytest.mark.usefixtures("run_dirs")
def test_parse_synthetic_wset(fixtures):
    dev = Easygen3500XT.parse(fixtures["synthetic.wset"])
    assert dev.description.model == "3200XT-P1"
    assert dev.description.product == "easYgen-3200XT-P1"
    assert dev.firmware.id == "EG3200XTP1 2.12-0_50976"
    assert len(dev.extra["parameters"]) == 4
    assert len(dev.registers) == 4  # ServLink handles only, no CANopen multiplexors
    assert dev.name == "Genset 7"
    assert dev.extra["device_number"] == 7
    assert dev.logic.parsed == ""  # no LogicsManager equations in the synthetic file
    assert not list(dev.get_out_dir().rglob("logic.st"))


@pytest.mark.parametrize("key", ["sid", "xml.sid"])
@pytest.mark.usefixtures("run_dirs")
def test_parse_sid(fixtures, assert_glob_path, key):
    dev = Easygen3500XT.parse(fixtures[key])
    assert dev.description.model == "3200XT-P1"
    assert dev.firmware.version == "2.12-0"
    assert dev.extra["sid"]["num_parameters"] == 7
    assert [u.name for u in dev.users] == ["service"]
    assert_glob_path(dev.get_out_dir(), "parsed-sid.json")


@pytest.mark.usefixtures("run_dirs")
def test_parse_wtool(fixtures, assert_glob_path):
    dev = Easygen3500XT.parse(fixtures["wtool"])
    assert dev.description.model == "3200XT-P1"
    assert dev.extra["wtool"]["name"] == "EG3000XT"
    assert dev.extra["wtool"]["device_names"] == ["ToolConfigurator"]
    assert_glob_path(dev.get_out_dir(), "parsed-wtool.json")


@pytest.mark.usefixtures("run_dirs")
def test_parse_tc_easygen(fixtures, assert_glob_path):
    dev = Easygen3500XT.parse(fixtures["easygen.tc"])
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3500"  # from the application identifier
    assert dev.description.product == "easYgen-3500"
    assert dev.type == "Genset Controller"
    assert dev.firmware.id == EASYGEN_APPLICATION
    assert dev.extra["tc"]["num_parameters"] == 7
    assert len(dev.extra["parameters"]) == 7
    assert_glob_path(dev.get_out_dir(), "parsed-tc.json")


@pytest.mark.usefixtures("run_dirs")
def test_easygen_rejects_tc_of_other_controls(fixtures):
    assert Easygen3500XT.parse(fixtures["tc"]) is None


@pytest.mark.usefixtures("run_dirs")
def test_parse_tc_2301e(fixtures, assert_glob_path):
    dev = WDW2301E.parse(fixtures["tc"])
    assert dev.description.model == "2301E"
    assert dev.description.vendor.id == "Woodward"
    assert dev.firmware.id == TC_FIXTURE_APPLICATION
    assert dev.extra["tc"]["version"] == "1.0"
    assert len(dev.extra["parameters"]) == 7
    assert_glob_path(dev.get_out_dir(), "parsed-tc.json")


@pytest.mark.usefixtures("run_dirs")
def test_2301e_rejects_other_files(fixtures):
    assert WDW2301E.parse(fixtures["synthetic.wset"]) is None
    assert WDW2301E.parse(fixtures["easygen.tc"]) is None


@pytest.mark.usefixtures("run_dirs")
def test_2301e_parse_error(fixtures, mocker, caplog):
    mocker.patch("peat.modules.woodward.wdw_2301e.parse_tc", side_effect=ValueError("bad data"))
    assert WDW2301E.parse(fixtures["tc"]) is None
    assert "bad data" in caplog.text


@pytest.mark.usefixtures("run_dirs")
def test_parse_raw_bytes_uses_signatures(fixtures):
    # Raw data has no filename, so the file signature names it
    dev = Easygen3500XT.parse(fixtures["synthetic.wset"].read_bytes())
    assert dev is not None
    assert dev.id == "settings"
    # The configured device name takes precedence over the id, as for other parsed devices
    assert dev.get_id() == "Genset 7"
    assert dev.description.model == "3200XT-P1"

    dev = Easygen3500XT.parse(fixtures["easygen.tc"].read_bytes())
    assert dev.get_id() == "tunables"
    assert dev.extra["tc"]["num_parameters"] == 7


@pytest.mark.usefixtures("run_dirs")
def test_parse_unknown_file(tmp_path):
    path = tmp_path / "input" / "mystery.wset"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"this is not a settings file")
    assert Easygen3500XT.parse(path) is None  # parse_wset() fails on the content

    path = tmp_path / "input" / "mystery.bin"
    path.write_bytes(b"this is not anything")
    with pytest.raises(Exception, match="Unknown Woodward file type"):
        Easygen3500XT.parse(path)


@pytest.mark.parametrize("key", ["synthetic.wset", "sid", "wtool", "easygen.tc"])
@pytest.mark.usefixtures("run_dirs")
def test_parse_parser_error(fixtures, mocker, caplog, key):
    kind = key.rpartition(".")[2]
    populate = WOODWARD_FILE_PARSERS[kind][1]
    parse = mocker.Mock(side_effect=ValueError("bad data"))
    mocker.patch.dict(WOODWARD_FILE_PARSERS, {kind: (parse, populate)})
    assert Easygen3500XT.parse(fixtures[key]) is None
    parse.assert_called_once()
    assert "bad data" in caplog.text

    mocker.patch.dict(WOODWARD_FILE_PARSERS, {kind: (mocker.Mock(return_value={}), populate)})
    assert Easygen3500XT.parse(fixtures[key]) is None


@pytest.mark.usefixtures("run_dirs")
def test_parse_directory_is_rejected(tmp_path):
    directory = tmp_path / "input"
    directory.mkdir(exist_ok=True)
    with pytest.raises(Exception, match="Directories aren't supported"):
        Easygen3500XT._parse(directory)


@pytest.mark.slow
def test_cli_parse_wset(exec_peat, tmp_path, fixtures, assert_glob_path, assert_meta_files):
    result = exec_peat(
        [
            "parse",
            "--print-results",
            "-d",
            "easygen",
            "--run-dir",
            tmp_path.as_posix(),
            fixtures["wset"].as_posix(),
        ]
    )
    assert result.returncode == 0, result.stderr.decode()
    # The printed results are the parse summary
    printed = json.loads(result.stdout.decode())
    assert printed["num_parse_successes"] == 1
    assert printed["num_parse_failures"] == 0
    assert printed["parse_results"][0]["module"] == "Easygen3500XT"
    device = printed["parse_results"][0]["results"]
    assert device["description"]["model"] == "3500"
    assert device["firmware"]["id"] == "5418-6722-NEW"
    assert device["extra"]["wset"]["num_parameters"] == 2756
    summary = json.loads(assert_glob_path(tmp_path, "parse-summary.json").read_text("utf-8"))
    assert summary["parse_results"] == printed["parse_results"]
    assert_glob_path(tmp_path, "parsed-wset.json")
    assert_meta_files()


@pytest.mark.slow
def test_cli_parse_directory_auto_detects_modules(exec_peat, tmp_path, fixtures):
    # No module given: files are matched to modules by name pattern and signature
    input_dir = fixtures["wset"].parent
    result = exec_peat(["parse", "--run-dir", tmp_path.as_posix(), input_dir.as_posix()])
    assert result.returncode == 0, result.stderr.decode()
    summary = json.loads((tmp_path / "summaries" / "parse-summary.json").read_text("utf-8"))
    parsed = {(r["module"], r["name"]) for r in summary["parse_results"]}
    assert ("Easygen3500XT", fixtures["wset"].name) in parsed
    assert ("Easygen3500XT", fixtures["sid"].name) in parsed
    assert ("Easygen3500XT", fixtures["wtool"].name) in parsed
    # Each .tc file is parsed by one module, depending on its application
    assert ("Easygen3500XT", fixtures["easygen.tc"].name) in parsed
    assert ("WDW2301E", fixtures["tc"].name) in parsed
    assert ("Easygen3500XT", fixtures["tc"].name) not in parsed
    assert ("WDW2301E", fixtures["easygen.tc"].name) not in parsed
    assert summary["num_parse_failures"] == 0


@pytest.mark.slow
def test_cli_parse_stdin(tmp_path, fixtures):
    result = run(
        [
            sys.executable,
            "-m",
            "peat",
            "parse",
            "-q",
            "-E",
            "-d",
            "easygen",
            "--run-dir",
            tmp_path.as_posix(),
            "-",
        ],
        input=fixtures["synthetic.wset"].read_bytes(),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    printed = json.loads(result.stdout.decode())
    assert printed["num_parse_successes"] == 1
    assert printed["parse_results"][0]["name"] == "stdin"
    assert printed["parse_results"][0]["results"]["description"]["model"] == "3200XT-P1"
