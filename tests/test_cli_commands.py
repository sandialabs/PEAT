import json
import shutil
import sys

import pytest

import peat.api.scan_api
from peat import __version__


@pytest.mark.slow
def test_cli_parse_non_existing_file(exec_peat, tmp_path, assert_meta_files):
    bad_filename = "INVALIDFILE.TXT.PS.INVALID"
    args = [
        "parse",
        "--print-results",
        "-d",
        "m340",
        "--run-dir",
        tmp_path.as_posix(),
        bad_filename,
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stdout  # no output from failed parse

    output = result.stderr.decode()
    assert bad_filename in output
    assert "ERROR" in output
    assert "Path doesn't exist" in output
    assert_meta_files()


@pytest.mark.slow
def test_cli_push_non_existing_file(exec_peat, tmp_path, assert_meta_files):
    bad_filename = "INVALIDFILE.TXT.PS.INVALID"
    args = [
        "push",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "controllogix",
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
        bad_filename,
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stdout  # no output from failed push

    output = result.stderr.decode()
    assert bad_filename in output
    assert "ERROR" in output
    assert "bad input source" in output
    assert_meta_files()


@pytest.mark.slow
def test_cli_pull_results_file_localhost(
    exec_peat, datapath, tmp_path, assert_meta_files, assert_no_criticals
):
    path = datapath("test-scan-results-localhost-clx.json")
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-f",
        path.as_posix(),
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for localhost
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
@pytest.mark.parametrize(
    "device_name", ["m340", "controllogix", "siprotec", "selrelay", "micronet"]
)
def test_cli_pull_devices_localhost(
    exec_peat,
    tmp_path,
    device_name,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        device_name,
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for localhost
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_pull_fake_subnet(exec_peat, tmp_path, assert_meta_files, assert_no_criticals):
    """
    RFC 5737 - IPv4 Address Blocks Reserved for Documentation
    https://tools.ietf.org/html/rfc5737
    """
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "controllogix",
        "-i",
        "192.0.2.0/24",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for fake subnet
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_results_file_localhost(
    run_peat,
    datapath,
    tmp_path,
    assert_meta_files,
    assert_no_criticals,
):
    path = datapath("test-scan-results-localhost-clx.json")
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-f",
        path.as_posix(),
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert "hosts_verified" in output
    assert output["scan_type"] == "unicast_ip"
    assert "ControlLogix" in output["scan_modules"]
    assert output["peat_version"] == __version__
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
@pytest.mark.parametrize("device_name", ["m340", "controllogix", "siprotec", "selrelay", "sel"])
def test_cli_scan_devices_short_timeout(
    run_peat,
    tmp_path,
    device_name,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        device_name,
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert "hosts_verified" in output
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert device_name in str(output["scan_modules"]).lower()
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_all_devices_short_timeout(
    run_peat,
    tmp_path,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_all_devices_short_timeout_duplicate_host(run_peat, tmp_path, assert_meta_files):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "127.0.0.1",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()


@pytest.mark.slow
def test_cli_dry_run(run_peat, tmp_path, mocker, assert_meta_files, assert_no_errors):
    mocker.patch("peat.api.scan_api.scan", return_value=None)

    args = [
        "scan",
        "--dry-run",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "127.0.0.1",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = run_peat(args)[1]

    assert "finished" in output.lower()
    assert "dry run" in output.lower()
    assert "num_hosts_verified" not in output
    # Ensure scan() wasn't called during the dry run
    assert not peat.api.scan_api.scan.called
    assert_meta_files()
    assert_no_errors()


@pytest.mark.slow
def test_cli_scan_localhost_subnet(run_peat, tmp_path, assert_meta_files):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "clx",
        "-i",
        "127.0.0.0/28",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()


@pytest.mark.slow
def test_cli_encryption(run_peat, tmp_path, examples_dir, read_text, datapath):
    testing_path = tmp_path / "config"
    testing_path.mkdir()
    path_to_config = f"{testing_path.as_posix()}/example_config.yaml"
    sys.stdin = "password"
    args = [
        "encrypt",
        "-f",
        path_to_config,
        "-p",
        "testpass",
        "--run-dir",
        tmp_path.as_posix(),
    ]
    config_original = f"{examples_dir.as_posix()}/encryption/example_config.yaml"
    shutil.copy(src=config_original, dst=path_to_config)
    run_peat(args)[0]

    assert read_text(datapath(f"{testing_path.as_posix()}/encrypted_example_config.yaml"))


@pytest.mark.slow
def test_cli_decryption(run_peat, tmp_path, examples_dir, read_text, datapath):
    testing_path = tmp_path / "config"
    testing_path.mkdir()
    # create a path to the encrypted file in tmp_path we'll attempt to decrypt
    path_to_config = f"{testing_path.as_posix()}/encrypted_config.yaml"
    # create a path to the original config in /examples/encryption
    config_original = f"{examples_dir.as_posix()}/encryption/encrypted_config.yaml"

    args = [
        "decrypt",
        "-f",
        path_to_config,
        "-p",
        "a",  # 'a' is just the password used to encrypt the original encrypted_config.yaml
        "-w",
        testing_path,
        "--run-dir",
        tmp_path.as_posix(),
    ]
    shutil.copy(src=config_original, dst=path_to_config)
    run_peat(args)[0]

    assert read_text(datapath(f"{testing_path.as_posix()}/decrypted_config.yaml"))
