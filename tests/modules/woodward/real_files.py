"""
The real easYgen-3500 ToolKit settings files in ``examples/devices/woodward/easygen-3500/``
(see the README.md there), shared by the Woodward tests.

Both files are from the same easYgen-3500 (ToolKit application ``5418-6722-NEW``)
and have the same parameters, only some of the values differ.
"""

import gzip
from functools import cache
from pathlib import Path
from typing import Any, Final

import pytest

from peat.modules.woodward.parse_wset import parse_wset

#: Directory with the example easYgen-3500 settings files
EASYGEN_EXAMPLES_DIR: Final[Path] = (
    Path(__file__).resolve().parents[3] / "examples" / "devices" / "woodward" / "easygen-3500"
)

#: 4 MVA diesel genset settings file, most file specific assertions are for this file
DIESEL_WSET: Final[str] = "4_MVA_Diesel_20161116.wset"

#: 3.5 MVA natural gas genset settings file
NG_WSET: Final[str] = "3_5MVA_NGGenset20161116.wset"

#: Names of the real settings files (decompressed)
REAL_WSET_FILES: Final[tuple[str, ...]] = (DIESEL_WSET, NG_WSET)

#: Parameters for tests that are too slow to run on every file by default:
#: the diesel file always, the natural gas file with ``--run-slow``
REAL_WSET_PARAMS_SLOW: Final[list[Any]] = [
    pytest.param(DIESEL_WSET, id="diesel"),
    pytest.param(NG_WSET, id="ng", marks=pytest.mark.slow),
]


def real_wset_gz(name: str) -> Path:
    """Path of the compressed example file."""
    path = EASYGEN_EXAMPLES_DIR / f"{name}.gz"
    assert path.is_file(), f"Example file missing: {path}"
    return path


@cache
def real_wset_bytes(name: str) -> bytes:
    """The decompressed example file."""
    return gzip.decompress(real_wset_gz(name).read_bytes())


@cache
def real_wset_parsed(name: str) -> dict[str, Any]:
    """
    :func:`~peat.modules.woodward.parse_wset.parse_wset` output for the
    example file. Parsed once per test session, don't modify it.
    """
    return parse_wset(real_wset_bytes(name))
