import filecmp
import json

import pytest

from peat import config, datastore, module_api


def test_awesome_module_load_and_parse(mocker, tmp_path, example_module_file):
    """
    Test that the module integrates as expected (it's a working module).
    """
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

    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())

    assert module_api.import_module(example_module_file("awesome_module.py")) is True

    source_file = example_module_file("awesome_output.json")
    parsed_device = module_api.modules["awesometool"].parse(source_file)
    assert filecmp.cmp(parsed_device._out_dir / source_file.name, source_file)

    expected = json.loads(
        example_module_file("awesome_output_expected_device-data-full.json").read_text()
    )
    assert parsed_device.export() == expected


@pytest.mark.slow
def test_import_awesome_module_parse_cli(run_peat, tmp_path, example_module_file):
    args = [
        "parse",
        "-q",
        "--print-results",
        "-o",
        tmp_path.as_posix(),
        "-d",
        "AwesomeTool",
        "-I",
        example_module_file("awesome_module.py").as_posix(),
        "--",
        example_module_file("awesome_output.json").as_posix(),
    ]

    results = json.loads(run_peat(args)[0])["parse_results"][0]["results"]
    expected = json.loads(
        example_module_file("awesome_output_expected_device-data-full.json").read_text()
    )

    assert results == expected


@pytest.mark.slow
def test_import_awesome_module_parse_cli_no_device_type(run_peat, tmp_path, example_module_file):
    """
    Regression test for bug fixed on 04/20/2023.
    The following command would fail with a confusing exception, due to lack of "-d" argument:
        peat parse -I ./examples/example_peat_module/awesome_module.py -- ./examples/example_peat_module/awesome_output.json
    """  # noqa: E501
    args = [
        "parse",
        "-q",
        "--print-results",
        "-o",
        tmp_path.as_posix(),
        "-I",
        example_module_file("awesome_module.py").as_posix(),
        "--",
        example_module_file("awesome_output.json").as_posix(),
    ]

    results = json.loads(run_peat(args)[0])["parse_results"][0]["results"]
    expected = json.loads(
        example_module_file("awesome_output_expected_device-data-full.json").read_text()
    )

    assert results == expected
