import filecmp
from pathlib import Path

import pytest

from peat import L5X, config, datastore

# !!! NOTE !!!
# If the output format changed and the tests are failing, then regenerate
# the expected output files using the test file regen script :)
# "pdm run python tests/generate_test_data_files.py L5X"


# TODO: re-generate test data from the open-source repos
# Note that the point of these tests is to validate PEAT's
# post-processing of L5X file data into the data model. Most
# of the lower-level parsing is handled by the open-source
# "l5x" python package: https://github.com/jvalenzuela/l5x
data_files = [
    # Default GitHub license
    # https://github.com/drbitboy/plc_rng
    "plc_rng/A_Gauss_RNG.L5X",
    "plc_rng/a_RMPS.L5X",
    "plc_rng/A_Uniform_RNG.L5X",
    "plc_rng/Random_AOI_Test_01042020.L5X",
    # GPLv3 license
    # https://github.com/jmorit/l5x_test/tree/master/l5x_jm
    "basetest.L5X",
]


# TODO: Re-add l5x tests from open-source examples after open sourcing
# https://github.com/drbitboy/plc_rng
# https://github.com/jmorit/l5x_test/tree/master/l5x_jm
@pytest.mark.skip("Re-add l5x tests from open-source examples after open sourcing")
@pytest.mark.parametrize("input_path", data_files)
def test_parse_l5x(
    json_data,
    tmp_path,
    mocker,
    dev_data_compare,
    assert_glob_path,
    input_path,
    examples_dir,
):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "device_results",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])

    source_file = Path(examples_dir, "devices", "l5x", input_path)

    dev = L5X.parse(source_file)

    # Check the exported data without the raw data nearly matches what's expected
    exported_summary = dev.export_summary()
    dev_data_compare(
        json_data(f"{source_file.stem}_expected_device-data-summary.json"),
        exported_summary,
    )

    # Check the exported full data nearly matches what's expected
    exported_full = dev.export(include_original=True)
    dev_data_compare(
        json_data(f"{source_file.stem}_expected_device-data-full.json"), exported_full
    )

    assert dev.logic.hash.sha256 == dev.logic.file.hash.sha256

    with source_file.open(encoding="utf-8", newline="") as f:
        assert dev.logic.original == f.read()

    assert filecmp.cmp(dev._out_dir / source_file.name, source_file)  # type: ignore
    assert_glob_path(dev._out_dir, "device-data-summary.json")
    assert_glob_path(dev._out_dir, "device-data-full.json")
