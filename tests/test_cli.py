import json
import os

import pytest
import yaml

from peat import __version__, cli_args
from peat.heat import HEAT_EXTRACTORS


@pytest.mark.slow
@pytest.mark.parametrize("exec_args", [None, ["--help"]])
def test_cli_help(run_peat, exec_args):
    result = run_peat(exec_args)[0]
    assert "PEAT: Process Extraction and Analysis Tool" in result
    assert "usage: peat [-h] [--version]" in result


all_base = (
    "-h, --help",
    "-v, --verbose",
    "-V, --debug",
    "--list-modules",
    "--examples",
    "--all-examples",
)
# NOTE: in python 3.13, "-f FILE, --host-file FILE" is now "-f, --host-file FILE"
active_base = ("--host-file FILE", "-i HOSTS", "-s PORTS")


@pytest.mark.slow
@pytest.mark.parametrize(
    ("subcmd", "expected"),
    [
        ("scan", [*all_base, *active_base, "--peat-modules TYPES "]),
        ("parse", [*all_base, "--peat-modules TYPES"]),
        ("pull", [*all_base, *active_base, "--peat-modules TYPE "]),
        ("push", [*all_base, *active_base, "input_source", "--peat-modules DEVICE "]),
        ("pillage", [*all_base, "-P SOURCE"]),
        ("heat", [*all_base, "--heat-file-only"]),
        (
            "decrypt",
            [
                *all_base,
                "-f",
                "--file-path FILE",
                "-w",
                "--write-file DIR",
                "-p",
                "--password USER_PASS",
            ],
        ),
        (
            "encrypt",
            [
                *all_base,
                "-f",
                "--file-path FILE",
                "-p",
                "--password USER_PASS",
            ],
        ),
    ],
)
def test_cli_subcommand_help(run_peat, subcmd, expected):
    no_arg_result = run_peat([subcmd])[0]

    assert f"usage: peat {subcmd}" in no_arg_result
    for arg in expected:
        assert arg in no_arg_result

    help_arg_result = run_peat([subcmd, "--help"])[0]

    assert f"usage: peat {subcmd}" in help_arg_result
    for arg in expected:
        assert arg in help_arg_result


@pytest.mark.slow
@pytest.mark.parametrize("subcmd", ["scan", "parse", "pull", "push", "pillage", "heat"])
def test_cli_list_modules(run_peat, subcmd):
    output = run_peat([subcmd, "--list-all"])[0]
    assert "** Modules **" in output
    assert "** Aliases **" in output
    assert "'clx'" in output

    assert "ControlLogix" in run_peat([subcmd, "--list-modules"])[0]

    assert '"clx"' in run_peat([subcmd, "--list-aliases"])[0]

    mappings_output = run_peat([subcmd, "--list-alias-mappings"])[0]
    assert '"clx"' in mappings_output
    assert '"ControlLogix"' in mappings_output


@pytest.mark.slow
@pytest.mark.parametrize("subcmd", ["scan", "parse", "pull", "push", "pillage", "heat"])
def test_cli_examples(run_peat, subcmd):
    examples = run_peat([subcmd, "--examples"])[0].replace("\r\n", "\n")
    all_examples = run_peat([subcmd, "--all-examples"])[0].replace("\r\n", "\n")

    assert examples.strip() == cli_args.ALL_EXAMPLES[subcmd].strip()
    assert cli_args.ALL_EXAMPLES[subcmd].strip() in all_examples


@pytest.mark.slow
def test_cli_heat_list_protocols(run_peat):
    result = run_peat(["heat", "--list-heat-protocols"])[0]
    assert all(p.__name__ in result for p in HEAT_EXTRACTORS)
    assert len(list(result.splitlines())) == 1


@pytest.mark.slow
def test_cli_version(run_peat):
    assert run_peat(["--version"])[0] == f"PEAT {__version__}"


@pytest.mark.slow
@pytest.mark.parametrize("arg", ["--verbose", "-V", "-VV", "-vV"])
def test_cli_verbose_arguments(run_peat, tmp_path, mocker, arg):
    mocker.patch.dict(
        os.environ,
        {
            "PEAT_NO_LOGO": "false",
            # enable colors (they're disabled by default in conftest.py)
            "PEAT_NO_COLOR": "false",
        },
    )

    args = [
        "scan",
        arg,
        "--print-results",
        "-d",
        "clx",
        "-i",
        "localhost",
        "-T",
        "0.01",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    # Ensure there are colors in output (if not on Windows)
    if os.name != "nt":
        assert "\033[1m" in stderr

    assert stdout
    assert "/   /_____/_/  |_/_/" in stderr  # ensure logo is present
    assert __version__ in stderr  # ensure version in logo + scan results
    assert __version__ in stdout
    assert "hosts_verified" in json.loads(stdout)  # standard scan result output
    assert "CRITICAL" not in stderr


@pytest.mark.slow
@pytest.mark.parametrize("arg", ["--verbose", "-V", "-VV", "-vV"])
def test_cli_no_colors(run_peat, tmp_path, mocker, arg):
    """Ensure there are no colors in output if colored output is disabled."""
    mocker.patch.dict(
        os.environ,
        {
            "PEAT_NO_LOGO": "false",
            "PEAT_NO_COLOR": "true",  # ensure colors are disabled
        },
    )
    args = [
        "scan",
        "--print-results",
        "-T",
        "0.01",
        arg,
        "-d",
        "clx",
        "-i",
        "localhost",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert stdout
    assert "\033[1m" not in stderr
    assert "/   /_____/_/  |_/_/" in stderr  # ensure logo is present
    assert __version__ in stderr  # ensure version in logo + scan results
    assert __version__ in stdout
    assert "hosts_verified" in json.loads(stdout)  # standard scan result output
    assert "CRITICAL" not in stderr


@pytest.mark.slow
@pytest.mark.parametrize("arg", ["--no-logo", "--quiet", "-vq"])
def test_cli_quiet_arguments(run_peat, tmp_path, mocker, arg):
    """
    No logo output (--no-logo).
    Quiet mode (--quiet).
    Quiet mode isn't affected by verbose output (-vq).
    """
    mocker.patch.dict(os.environ, {"PEAT_NO_LOGO": "false"})
    args = [
        "scan",
        "--print-results",
        "-T",
        "0.01",
        arg,
        "-d",
        "clx",
        "-i",
        "localhost",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert stdout
    assert "hosts_verified" in json.loads(stdout)  # standard scan result output
    assert "/   /_____/_/  |_/_/" not in stderr  # ensure logo is NOT present
    assert "CRITICAL" not in stderr


@pytest.mark.slow
@pytest.mark.parametrize("arg", ["--no-color", "--no-logo"])
def test_cli_quiet_combos(run_peat, tmp_path, mocker, arg):
    """
    Quiet mode isn't affected by no colored output (-q --no-color).
    Quiet mode isn't affected by no logo output (-q --no-logo).
    """
    mocker.patch.dict(os.environ, {"PEAT_NO_LOGO": "false", "PEAT_NO_COLOR": "false"})
    args = [
        "scan",
        "-q",
        "--print-results",
        arg,
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert not stderr  # ensure no output (-q argument)
    assert "hosts_verified" in json.loads(stdout)  # standard scan result output


@pytest.mark.slow
def test_cli_quiet_no_output(run_peat, tmp_path, mocker):
    mocker.patch.dict(os.environ, {"PEAT_NO_LOGO": "false"})
    args = [
        "scan",
        "--quiet",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)
    assert not stdout
    assert not stderr


@pytest.mark.slow
def test_cli_logo(run_peat, tmp_path, mocker):
    """
    Ensure logo is printed.
    """
    mocker.patch.dict(os.environ, {"PEAT_NO_LOGO": "false"})
    args = [
        "scan",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert not stdout  # no results if --print-results isn't specified
    assert "hosts_verified" not in stderr
    assert "/   /_____/_/  |_/_/" in stderr
    assert stderr.count(__version__) == 1  # only should be version in logo
    assert "CRITICAL" not in stderr


@pytest.mark.slow
def test_cli_run_dir(run_peat, tmp_path):
    """
    Test --run-dir argument.
    """
    run_dir = tmp_path / "test_run_dir"
    args = [
        "scan",
        "--print-results",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "--run-dir",
        run_dir.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert stdout
    assert stderr

    # Check run dir exists, is the expected name, and doesn't
    # have README.md (which is usually added to OUT_DIR).
    assert run_dir.name == "test_run_dir"
    out_dir_files = [x.name for x in run_dir.iterdir()]
    assert not list(run_dir.glob("*README.md*"))
    assert len(out_dir_files) >= 3
    assert "logs" in out_dir_files


@pytest.mark.slow
def test_cli_run_name(run_peat, tmp_path):
    """
    Test --run-name argument.
    """
    run_name = "test_run_name_value"
    args = [
        "scan",
        "--print-results",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "--out-dir",
        tmp_path.as_posix(),
        "--run-name",
        run_name,
    ]

    stdout, stderr = run_peat(args)

    assert stdout
    assert stderr

    assert list(tmp_path.glob("README.md"))
    run_dir = tmp_path / run_name
    assert run_dir.is_dir()
    assert run_dir.name == run_name
    out_dir_files = [x.name for x in run_dir.iterdir()]
    assert not list(run_dir.glob("*README.md*"))
    assert len(out_dir_files) >= 3
    assert "logs" in out_dir_files


@pytest.mark.slow
def test_cli_config_file_yaml(run_peat, tmp_path, examples_path):
    """
    Loading configuration values from a YAML file doesn't fail (--config-file).
    Also, this checks if the RUN_DIR adds the name from the YAML config.
    """
    args = [
        "scan",
        "--print-results",
        "-vVV",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "--config-file",
        examples_path("peat-config.yaml").as_posix(),
        "--out-dir",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert stdout
    assert " loaded from " in stderr
    assert "peat-config.yaml" in stderr
    assert "hosts_verified" in json.loads(stdout)
    assert "CRITICAL" not in stderr

    # Check run dir has config name
    out_dir_files = sorted(tmp_path.iterdir())
    assert len(out_dir_files) == 2
    assert out_dir_files[0].name == "README.md"
    run_dir = out_dir_files[1]
    assert run_dir.is_dir()
    assert run_dir.name.startswith("scan_reference-peat-config_")

    # Ensure files actually written match those in state.written_files
    state_file = next(iter((run_dir / "peat_metadata").glob("peat_state.yaml")))
    state_data = yaml.safe_load(state_file.read_text(encoding="utf-8"))
    written_files = sorted(state_data["written_files"])
    actual_files = sorted([x.as_posix() for x in tmp_path.rglob("*.*")])
    assert written_files == actual_files


@pytest.mark.slow
def test_cli_config_file_json(run_peat, tmp_path, datapath):
    """
    Loading configuration values from a JSON file doesn't fail (--config-file).
    """
    args = [
        "scan",
        "--print-results",
        "-vVV",
        "-T",
        "0.01",
        "-d",
        "clx",
        "-i",
        "localhost",
        "--config-file",
        datapath("example-peat-configuration.json").as_posix(),
        "-o",
        tmp_path.as_posix(),
    ]

    stdout, stderr = run_peat(args)

    assert stdout

    assert " loaded from " in stderr
    assert "example-peat-configuration.json" in stderr
    assert "hosts_verified" in json.loads(stdout)
    assert "CRITICAL" not in stderr

    # Check run dir
    out_dir_files = sorted(tmp_path.iterdir())
    assert len(out_dir_files) == 2
    assert out_dir_files[0].name == "README.md"
    run_dir = out_dir_files[1]
    assert run_dir.is_dir()
    assert run_dir.name.startswith("scan_example-peat-configuration_")

    # Ensure files actually written match those in state.written_files
    state_file = next(iter((run_dir / "peat_metadata").glob("peat_state.yaml")))
    state_data = yaml.safe_load(state_file.read_text(encoding="utf-8"))
    written_files = sorted(state_data["written_files"])
    actual_files = sorted([x.as_posix() for x in tmp_path.rglob("*.*")])
    assert written_files == actual_files
