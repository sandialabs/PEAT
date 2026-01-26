import tempfile
from pathlib import Path
from typing import Any

from .csharp_reader import *


def parse_wset(_file: Any):
    # Determine if valid file type
    if isinstance(_file, Path):
        streamfile = open(_file, "rb")
    elif isinstance(_file, bytes):
        fp = tempfile.NamedTemporaryFile(mode="w+b", delete=False)
        fp.write(_file)
        fp.seek(0)
        streamfile = fp
    else:
        raise Exception("unknown file type for wset parsing")

    # Omit first 10 bytes due to Woodward-proprietary header
    streamfile.seek(10)

    # TODO: use netfleece instead since it seems to be better
    # and produces (relatively) reasonabilty sized files
    # https://gitlab.com/malie-library/netfleece

    json_encoder = JSONEncoder(indent=4)
    output_dict = {}
    i = 0

    while True:
        output_dict[i] = json_encoder.encode(read_stream(streamfile))
        i += 1
        if streamfile.peek(1) == b"":
            break

    for index, value in output_dict.items():
        with open(f"out_{index}", "w") as outfile:
            print(value, file=outfile)

    # TODO: call streamfile.close()?
    return output_dict
