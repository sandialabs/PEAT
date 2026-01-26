"""
Main method that parses ``*file_hashes*.txt`` files and creates UEFIHash
objects to add to a device.

Authors:

- Danyelle Loffredo
- Tarun Menon
"""

from pathlib import Path

from peat import log
from peat.data.models import UEFIHash


def parse_hash(file_path: Path) -> list[UEFIHash]:
    """

    Args:
        file_path: Pathlib object file of hashes to parse

    Return:
        files_to_return: list of UEFIHash objects
    """
    files = []

    try:
        with file_path.open("r") as reportobj:
            for line in reportobj:
                new_line = line.strip().split(":")

                if len(new_line) == 3:
                    obj = UEFIHash(
                        file_system=new_line[0].strip('",'),
                        pathname=new_line[1].strip('",'),
                        hash=new_line[2].strip(' ",'),
                    )
                    files.append(obj)
    except Exception as ex:
        log.warning(f"{file_path} file could not be opened: {ex}")

    return files
