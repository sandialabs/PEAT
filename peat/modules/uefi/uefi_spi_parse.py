"""
Main parsing method for SPI.report files from UEFIExtract.
Parses the file and creates UEFIFile objects to add to a UEFI device.
Will only parse ``*bin.txt`` report files.

Authors:

- Danyelle Loffredo
- Tarun Menon
"""

import os
from datetime import datetime
from pathlib import Path

from peat import log
from peat.data.models import UEFIFile


def size_obj(
    len_obj: int, thingToAppend: list[str], nest_split: list[str], time_to_add: datetime
) -> UEFIFile:
    """
    Function to check for whether a file has a GUID or not.
    GUID is optional and is automatically set to an empty string.

    Args:
        len_obj: length of the list of things to append
        thingToAppend: List of objects in a single line from the report
        nest_split: list of UEFIFIle objects to keep track of path
        time_to_add: time the file was created

    Returns:
        list: a UEFIFile Object based on if a guid is present or not
    """
    if len_obj == 7:
        return UEFIFile(
            type=thingToAppend[0],
            subtype=thingToAppend[1],
            base=thingToAppend[2],
            size=thingToAppend[3],
            crc32=thingToAppend[4],
            guid=" ".join(nest_split[1:]),
            name=thingToAppend[6],
            created=time_to_add,
        )

    return UEFIFile(
        type=thingToAppend[0],
        subtype=thingToAppend[1],
        base=thingToAppend[2],
        size=thingToAppend[3],
        crc32=thingToAppend[4],
        name=" ".join(nest_split[1:]),
        created=time_to_add,
    )


def create_obj_append(
    thingToAppend: list[str],
    nest_split: list[str],
    stack: list[UEFIFile],
    time_to_add: datetime,
    files: list[UEFIFile],
) -> None:
    """
    Function that creates the UEFIFile object based on size.

    Args:
        thingToAppend: List of objects in a single line from the report
        nest_split: list of UEFIFIle objects to keep track of path
        stack: list of objects to keep track of path
        time_to_add: time the file was created
        files: list of all files
    """
    obj = size_obj(len(thingToAppend), thingToAppend, nest_split, time_to_add)
    obj.path = stack[-1].path + obj.name + "/"
    stack.append(obj)
    files.append(obj)


def parse_file(file_path: Path) -> list[UEFIFile]:
    """
    Main function that parses the reportfile.

    Args:
        reportfile: UEFITool extract SPI report text file

    Returns:
        List of all UEFIFile Objects that were created.
    """
    files = []

    try:
        with file_path.open("r") as reportobj:
            ti_c = os.path.getctime(file_path)
            x = datetime.fromtimestamp(ti_c)
            time_string = x
            stack = []
            number_of_nest = 0
            prev_num_nest = 0
            is_base = True

            for line in reportobj:
                newline = line.split("|")
                thingToAppend = list(map(str.strip, newline))
                nest_split = thingToAppend[5].split(" ")

                # ignore headers
                if nest_split[0] == "Name":
                    continue

                # first image doesn't follow the rest of the file so it is created \
                # outside of the create_obj_append function
                if "-" not in nest_split[0] and is_base:
                    obj = UEFIFile(
                        type=thingToAppend[0],
                        subtype=thingToAppend[1],
                        base=thingToAppend[2],
                        size=thingToAppend[3],
                        crc32=thingToAppend[4],
                        name=" ".join(nest_split[0:]),
                        path="/Image/",
                        created=time_string,
                    )
                    # put onto the stack to keep track of path
                    stack.append(obj)
                    files.append(obj)
                    is_base = False
                    obj = {}
                    continue

                number_of_nest = len(nest_split[0])

                if number_of_nest > prev_num_nest:
                    create_obj_append(thingToAppend, nest_split, stack, time_string, files)
                    prev_num_nest = number_of_nest
                    obj = {}
                    continue

                if number_of_nest == prev_num_nest:
                    stack.pop()
                    create_obj_append(thingToAppend, nest_split, stack, time_string, files)
                    obj = {}
                    continue

                if number_of_nest < prev_num_nest:
                    time_to_pop = prev_num_nest - number_of_nest

                    for _i in range(time_to_pop + 1):
                        stack.pop()

                    create_obj_append(thingToAppend, nest_split, stack, time_string, files)

                    prev_num_nest = number_of_nest
                    obj = {}
                    continue
    except Exception as ex:
        log.warning(f"{file_path} file could not be opened: {ex}")

    return files
