import pytest

from .real_files import REAL_WSET_FILES


@pytest.fixture(scope="module", params=REAL_WSET_FILES, ids=["diesel", "ng"])
def real_wset_name(request) -> str:
    """
    Name of a real easYgen-3500 example settings file (see ``real_files.py``).
    Tests using it run for each file. Tests can override the files with
    ``@pytest.mark.parametrize("real_wset_name", [...], indirect=True)``.
    """
    return request.param
