from pathlib import Path

from peat.api.pillage_api import check_file_conditions, is_valid_file, pillage, search

# TODO: actual tests of pillage functionality. This is just a stub.


def test_pillage_bad_args():
    assert pillage("") is False


def test_search():
    assert search(Path("NONEXISTENT"), None) is False


def test_is_valid_file(tmp_path):
    assert is_valid_file(tmp_path) == (False, "")


def test_check_file_conditions(tmp_path):
    assert check_file_conditions(tmp_path, {}) == (False, "")
    # TODO: test filename match
    # TODO: test extension match
