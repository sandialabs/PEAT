import filecmp

import pytest

from peat import SCEPTRE, config, datastore

# TODO: add additional files that didn't have tests, including:
#   sceptre-bennu/data/configs/ep/dnp3-client.xml
#   sceptre-bennu/data/configs/ep/dnp3-server.xml
#   sceptre-bennu/data/configs/ep/iec60870-5-104-client.xml
#   sceptre-bennu/data/configs/ep/iec60870-5-104-server.xml
#   sceptre-bennu/data/configs/ep/modbus-client.xml
data_files = [
    "bp-dnp3-client.xml",
    "bp-dnp3-server.xml",
    "bp-modbus-client.xml",
    "bp-modbus-server.xml",
    "ep-bacnet-client.xml",
    "ep-bacnet-server.xml",
    "ep-modbus-serial-client.xml",
    "ep-modbus-serial-server.xml",
    "ep-sunspec-server.xml",
]


# !!! NOTE !!!
# If the output format changed and the tests are failing, then regenerate
# the expected output files using the test file regen script :)
# "pdm run python tests/generate_test_data_files.py SCEPTRE"


# TODO: Re-add bennu tests from open-source sceptre-bennu after open sourcing
# https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs
@pytest.mark.skip("Re-add bennu tests from open-source sceptre-bennu after open sourcing")
@pytest.mark.parametrize("input_filename", data_files)
def test_parse_sceptre_fcd(
    json_data,
    tmp_path,
    mocker,
    datapath,
    dev_data_compare,
    assert_glob_path,
    input_filename,
    caplog,
):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp_results"},
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])

    source_path = datapath(input_filename)
    parsed_device = SCEPTRE.parse(source_path)

    # Check the exported data without the raw data nearly matches what's expected
    exported_summary = parsed_device.export_summary()
    dev_data_compare(
        json_data(f"{source_path.stem}_expected_device-data-summary.json"),
        exported_summary,
    )

    # Check the exported full data nearly matches what's expected
    exported_full = parsed_device.export(include_original=True)
    dev_data_compare(
        json_data(f"{source_path.stem}_expected_device-data-full.json"), exported_full
    )

    assert filecmp.cmp(parsed_device._out_dir / source_path.name, source_path)
    assert_glob_path(parsed_device._out_dir, "device-data-summary.json")
    assert_glob_path(parsed_device._out_dir, "device-data-full.json")

    # Ensure nothing abormal occurred
    assert "ERROR" not in caplog.text
    assert "CRITICAL" not in caplog.text
