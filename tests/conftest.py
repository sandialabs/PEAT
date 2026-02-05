"""
This file is used to configure pytest.

pytest documentation: https://docs.pytest.org/en/latest/contents.html

Explanation of conftest.py and other pytest features: https://stackoverflow.com/a/34520971
"""

import atexit
import json
import os
import sys
from datetime import datetime, UTC
from pathlib import Path
from platform import system, version
from subprocess import PIPE, CompletedProcess, Popen, run
from collections.abc import Callable

import pytest
from deepdiff import DeepDiff
from elasticsearch import Elasticsearch

from peat import config, exit_handler

# NOTE: we can't have arguments before subcommands anymore
PEAT_CMD = [sys.executable, "-m", "peat"]

# Exclude extraneous output
os.environ["PEAT_NO_LOGO"] = "true"
os.environ["PEAT_NO_COLOR"] = "true"

# Don't automatically resolve host-dependant values
os.environ["PEAT_RESOLVE_MAC"] = "false"
os.environ["PEAT_RESOLVE_IP"] = "false"
os.environ["PEAT_RESOLVE_HOSTNAME"] = "false"
config.RESOLVE_MAC = False
config.RESOLVE_IP = False
config.RESOLVE_HOSTNAME = False

# Prevent exit handlers from running when tests finish
atexit.unregister(exit_handler.run_handlers)


# This adds "--run-slow" and "--run-ci" as valid pytest CLI arguments
# https://docs.pytest.org/en/latest/example/simple.html
def pytest_addoption(parser):
    parser.addoption(
        "--run-slow", action="store_true", default=False, help="run slow tests"
    )
    parser.addoption(
        "--run-ci",
        action="store_true",
        default=False,
        help="run tests that are intended to be run only in the GitLab CI environment",
    )
    parser.addoption(
        "--run-broadcast-ci",
        action="store_true",
        default=False,
        help="run live broadcast tests intended to be used in GitLab CI on PEAT rack",
    )


def pytest_collection_modifyitems(config, items):
    # If --run-slow is not given in cli then skip
    # slow tests labelled with "pytest.mark.slow()".
    # Setting the environment variable "RUN_SLOW"
    # will also work to run the slow tests.
    if not config.getoption("--run-slow") and not (
        os.environ.get("RUN_SLOW") is not None
    ):
        skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Tests marked with "pytest.mark.gitlab_ci_only()"
    # will only be run if the "GITLAB_CI" environment
    # variable is present or if the CLI argument
    # "--run-ci" is given to pytest.
    # Tests that run only in CI should use system environment
    # variables to get their arguments (e.g. IP addresses).
    # The "GITLAB_CI" variable is automatically set by GitLab CI runners
    if not config.getoption("--run-ci") and (
        "live-tests" not in os.environ.get("CI_JOB_STAGE", "")
    ):
        skip_ci = pytest.mark.skip(
            reason="only run when run on a GitLab CI runner in "
            "the PEAT rack or if --run-ci is specified"
        )
        for item in items:
            if "gitlab_ci_only" in item.keywords:
                item.add_marker(skip_ci)

    # Tests marked with "pytest.mark.broadcast_ci()"
    if not config.getoption("--run-broadcast-ci"):
        skip_broadcast_ci = pytest.mark.skip(
            reason="only run when --run-broadcast-ci is specified"
        )
        for item in items:
            if "broadcast_ci" in item.keywords:
                item.add_marker(skip_broadcast_ci)


def pytest_assertrepr_compare(op, left, right):  # noqa: ARG001
    # Pretty print DeepDiff comparisons
    # https://docs.pytest.org/en/stable/assert.html
    if isinstance(left, dict) and isinstance(right, DeepDiff):
        changes = []
        if "values_changed" in right:
            changes.append("** Items CHANGED **")
            for k, v in right["values_changed"].items():
                changes.append(f"{k.replace('root', '')}")
                # TODO: highlight the specific differences between the values
                changes.append(f"\texpected: {v['old_value']}")
                changes.append(f"\tactual:   {v['new_value']}")

        if "dictionary_item_removed" in right:
            changes.append("** Items REMOVED **")
            for k in right["dictionary_item_removed"]:
                changes.append(f"\t{k.replace('root', '')}")

        if "dictionary_item_added" in right:
            changes.append("** Items ADDED **")
            for k in right["dictionary_item_added"]:
                changes.append(f"\t{k.replace('root', '')}")

        if not changes:
            changes.append("### Unknown changes, here's a raw dump ###")
            changes.append(str(right))

        return ["data differences", *changes]


@pytest.fixture
def deep_compare() -> Callable[[dict, dict, list | str | None], None]:
    def _deep_compare(
        first: dict, second: dict, exclude_regexes: list | str | None = None
    ) -> None:
        """
        Compare two objects and optionally exclude some elements from comparison.

        Regular expressions are used to exclude fields or paths from comparison.
        Refer to the DeepDiff documentation for details:
        `exclude_paths <https://zepworks.com/deepdiff/current/exclude_paths.html>`_

        If a test FAILS in GitLab CI due to difference in file size and hash,
        but doesn't fail locally, then ensure the line endings are set in
        .gitattributes ("eol=<endings>"). If not explicitly configured the
        line endings will vary based on the platform the repository is cloned
        to, e.g. the GitLab runner is on Linux and uses LF line endings while
        if you're working on Windows the default is CRLF (and Mac is something).

        If there are differences in device data output, then it may be the case that
        a change was made to a device module (e.g., adding additional fields) but the
        testing dataset wasn't updated yet. The fix may be as simple as regenerating
        the test data for that module, e.g. with tests/generate_test_data_files.py
        """
        assert {} == DeepDiff(first, second, exclude_regex_paths=exclude_regexes)

    return _deep_compare


@pytest.fixture
def dev_data_compare(deep_compare: Callable) -> Callable[..., None]:
    def _dev_data_compare(
        expected: dict, actual: dict, additional_regexes: str | list | None = None
    ) -> None:
        # TODO: method to check excluded keys exist even if values don't match
        # TODO: method to extract path for comparison,
        #   e.g. directory, to assert some property about it.
        #   for example, if directory path contains "/" characters,
        #   or a hash contains a valid hash value even if they don't match

        regexes = [r"\['(directory|path|owner|group|created|mtime|local_path)'\]"]

        if additional_regexes and isinstance(additional_regexes, str):
            regexes.append(additional_regexes)
        elif additional_regexes and isinstance(additional_regexes, list):
            regexes.extend(additional_regexes)

        deep_compare(expected, actual, regexes)

    return _dev_data_compare


@pytest.fixture
def assert_glob_path() -> Callable[[Path, str], Path]:
    """
    Recursively searches for file or directory matching the
    pattern (glob_str) in the directory specified (out_dir).
    The path to the file/directory found is returned.

    It checks the following:

    - Only ONE file matches the pattern
    - The file exists and is a valid file (readable)
    - The file has a non-zero size (has data)
    - JSON files will be validated as correct json (by loading them)
    """

    def _assert_glob_path(out_dir: Path, glob_str: str) -> Path:
        files = list(out_dir.rglob(glob_str))

        # Ensure only one file is generated
        assert len(files) == 1

        file_pth = files[0]

        # Ensure file exists and is a valid file
        assert file_pth.is_file()

        # Ensure the file has data
        assert file_pth.stat().st_size > 0

        # Check that JSON files are properly formatted
        if file_pth.suffix == ".json":
            with file_pth.open(encoding="utf-8") as fp:
                assert json.load(fp)

        return file_pth

    return _assert_glob_path


@pytest.fixture
def run_peat() -> Callable[..., tuple[str, str]]:
    """
    Executes PEAT CLI and returns string output from STDOUT.

    Returns:
        Tuple with decoded text from stdout and stderr
    """

    def _run_peat_wrapper(
        args: list[str] | None = None,
        shell: bool = False,
    ) -> tuple[str, str]:
        if not args:
            args = []

        if shell:  # If executing in a shell it should be a string
            command = " ".join(PEAT_CMD + args)
        else:  # Otherwise, it should be a list
            command = PEAT_CMD + args

        process = Popen(command, shell=shell, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if not process.returncode == 0:
            # Ensure stderr and stdout get printed on a failure
            print(f"stderr: {stderr.decode()}")  # noqa: T201
            print(f"stdout: {stdout.decode()}")  # noqa: T201
            assert process.returncode == 0

        return stdout.decode("utf-8").strip(), stderr.decode("utf-8").strip()

    return _run_peat_wrapper


@pytest.fixture
def exec_peat() -> Callable[..., CompletedProcess]:
    """
    Executes PEAT CLI and returns a ``subprocess.CompletedProcess`` object.
    """

    def _exec_peat_wrapper(
        args: list[str] | None = None,
        shell: bool = False,
        pre_cmd: str | None = None,
    ) -> CompletedProcess:
        if not args:
            args = []

        command = PEAT_CMD + args

        if pre_cmd:  # Examples: environment vars, piped input, etc.
            command: list = [pre_cmd, *command]
        if shell:  # In shell mode the command executed should be a string
            command = " ".join(command)

        return run(command, shell=shell, capture_output=True, check=False)

    return _exec_peat_wrapper


@pytest.fixture
def exec_command() -> Callable[[str, bool], CompletedProcess]:
    def _exec_command_wrapper(command: str, shell: bool = True) -> CompletedProcess:
        return run(command, shell=shell, capture_output=True, check=False)

    return _exec_command_wrapper


@pytest.fixture
def win_or_wsl() -> bool:
    return bool(
        system() == "Windows" or (system() == "Linux" and "Microsoft" in version())
    )


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def examples_path(examples_dir: Path) -> Callable[[str], Path]:
    def _examples_path(filename: str) -> Path:
        return Path(examples_dir, filename)

    return _examples_path


@pytest.fixture
def example_module_file(examples_dir: Path):
    def _example_module_file(filename: str) -> Path:
        return Path(examples_dir, "example_peat_module", filename)

    return _example_module_file


@pytest.fixture
def test_dir() -> Path:
    return Path(__file__).resolve().parent


@pytest.fixture
def top_datadir() -> Path:
    return Path(__file__).resolve().parent / "data_files"


@pytest.fixture
def top_datapath(top_datadir: Path):
    def _top_datapath(filename: str) -> Path:
        return Path(top_datadir, filename)

    return _top_datapath


@pytest.fixture(scope="module")
def datadir(request) -> Path:
    return Path(request.module.__file__).resolve().parent / "data_files"


@pytest.fixture(scope="module")
def datapath(datadir: Path):
    def _datapath(filename: str) -> Path:
        return Path(datadir, filename)

    return _datapath


@pytest.fixture(scope="module")
def read_text() -> Callable[[Path], str]:
    """
    Read text data from a file in a cross-platform way, with line endings
    returned as-is and NOT translated (in otherwords, disable universal newlines).

    Example: on Linux, file with "\r\n" will return a string with "\r\n",
    instead of having "\r\n" replaced with "\n".
    """

    def _read_text(filepath: Path) -> str:
        # newline="" ensures line endings are returned as-is and not translated.
        # e.g. a file with "\r\n" will return a string with "\r\n" instead of having
        # "\r\n" replaced with "\n".
        with filepath.open("r", encoding="utf-8", newline="") as infile:
            return infile.read()

    return _read_text


@pytest.fixture(scope="module")
def text_data(datadir: Path, read_text: Callable[[Path], str]):
    """
    Returns text data from a file in the test module's "data_files" directory.
    """

    def _read_text_data(filename: str) -> str:
        return read_text(Path(datadir, filename))

    return _read_text_data


@pytest.fixture(scope="module")
def json_data(datadir: Path) -> Callable[[str], dict | list | str]:
    """
    Loads data from a JSON file in the test module's "data_files" directory.
    """

    def _read_json(filename: str) -> dict | list | str:
        # NOTE: json module doesn't care about line endings
        return json.loads(Path(datadir, filename).read_text(encoding="utf-8"))

    return _read_json


@pytest.fixture(scope="module")
def binary_data(datadir: Path) -> Callable[[str], bytes]:
    def _read_bin(filename: str) -> bytes:
        return Path(datadir, filename).read_bytes()

    return _read_bin


@pytest.fixture(scope="module")
def es_client() -> Elasticsearch:
    es_host_url = os.environ.get("ES_URL", "http://es-server:9200")
    es_client = Elasticsearch(hosts=[es_host_url], verify_certs=False)

    # ensure we're able to reach the server
    assert es_client.ping()

    # ensure we have the right cluster
    assert "docker-cluster" in es_client.info()["cluster_name"]

    yield es_client
    es_client.close()


@pytest.fixture(scope="module")
def es_indices(es_client: Elasticsearch) -> list[str]:
    return [x.strip() for x in es_client.cat.indices(h="index").splitlines() if x]


@pytest.fixture(scope="module")
def curr_ydm() -> str:
    """
    WARNING: this may cause tests to fail if a test occurs near
    5PM MST (midnight UTC).
    """
    return datetime.now(UTC).strftime("%Y.%m.%d")


@pytest.fixture
def assert_no_warns(caplog) -> Callable:
    """
    Ensure nothing abormal occurred by looking for
    warnings and errors in log messages.
    This checks: WARNING, ERROR, and CRITICAL

    """

    def _assert_no_warns() -> None:
        assert "WARNING" not in caplog.text
        assert "ERROR" not in caplog.text
        assert "CRITICAL" not in caplog.text

    return _assert_no_warns


@pytest.fixture
def assert_no_errors(caplog) -> Callable:
    """
    Check for ERROR and CRITICAL only in log messages.
    """

    def _assert_no_errors() -> None:
        assert "ERROR" not in caplog.text
        assert "CRITICAL" not in caplog.text

    return _assert_no_errors


@pytest.fixture
def assert_no_criticals(caplog) -> Callable:
    """
    Check for CRITICAL in log messages.
    """

    def _assert_no_criticals() -> None:
        assert "CRITICAL" not in caplog.text

    return _assert_no_criticals


@pytest.fixture
def assert_meta_files(assert_glob_path, tmp_path) -> Callable:
    """
    Check that log and metadata files were created.
    This assumes the run dir is tmp_path, otherwise it can be
    passed as an argument.
    """

    def _assert_meta_files(run_dir=None) -> None:
        if not run_dir:
            run_dir = tmp_path

        assert_glob_path(run_dir / "logs", "peat.log")
        assert_glob_path(run_dir / "logs", "json-log.jsonl")
        assert_glob_path(run_dir / "logs", "debug-info.txt")
        assert_glob_path(run_dir / "peat_metadata", "peat_configuration.yaml")
        assert_glob_path(run_dir / "peat_metadata", "peat_state.yaml")

    return _assert_meta_files
