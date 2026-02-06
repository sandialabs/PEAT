import pytest

from peat import __version__, config, datastore
from peat.api.parse_api import parse


def test_parse_api_parse_bad_args(top_datapath, tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert parse(top_datapath("test_load_from_file.json"), ["nopeinvaliddev"]) is None
    assert parse(top_datapath("test_load_from_file.json"), []) is None
    assert parse([top_datapath("test_load_from_file.json")], ["nopeinvaliddev"]) is None
    assert parse([top_datapath("test_load_from_file.json")], []) is None


def test_parse_api_parse_failures(top_datapath, tmp_path, mocker, assert_glob_path):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    summary = parse([top_datapath("test_load_from_file.json")], ["SCEPTRE"])  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == ["SCEPTRE"]
    assert summary["input_paths"] == [top_datapath("test_load_from_file.json")]
    assert len(summary["files_parsed"]) == 1
    assert summary["num_files_parsed"] == 1
    assert summary["num_parse_successes"] == 0
    assert summary["num_parse_failures"] == 1
    assert len(summary["parse_failures"]) == 1
    assert not summary["parse_results"]

    assert_glob_path(parse_path, "parse-summary.json")


# TODO: Re-add bennu tests from open-source sceptre-bennu after open sourcing
# https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs
@pytest.mark.skip("Re-add bennu tests from open-source sceptre-bennu after open sourcing")
def test_parse_api_multiple_files(test_dir, tmp_path, mocker, assert_glob_path, assert_no_errors):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datafiles_path = test_dir / "modules" / "sandia" / "data_files"
    paths = [
        datafiles_path / "bp-dnp3-client.xml",
        datafiles_path / "ep-bacnet-client.xml",
        datafiles_path / "ep-sunspec-server.xml",
    ]
    modules = ["SCEPTRE", "SELRelay"]

    summary = parse(paths, modules)  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == modules
    assert "input_path" not in summary  # ensure old variable name isn't present
    assert summary["input_paths"] == paths
    assert len(summary["files_parsed"]) == 3
    assert summary["num_files_parsed"] == 3
    assert summary["num_parse_successes"] == 3
    assert summary["num_parse_failures"] == 0
    assert not summary["parse_failures"]
    assert len(summary["parse_results"]) == 3

    assert_glob_path(parse_path, "parse-summary.json")
    assert_no_errors()
