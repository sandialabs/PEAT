"""
Woodward Control Assistant Tunable Configuration .tc file parser.
"""

from peat import log


def _parse_tc_file(project):
    """
    Parse a *.tc device config file.

    Args:
        project: The .tc file prepared by parse_project

    Returns:
        A dictionary containing the device config
    """
    if project is None:
        log.error("No project specified")
        return {}
    if isinstance(project, bytes):
        project = project.decode()
    if not isinstance(project, str):
        log.error(f"Project type error: {type(project)!s}")
        return {}

    bad_lines = 0
    parsed_config = {}
    lines = project.strip().split("\r\n")

    file_ver_line = lines.pop(0)
    fw_prefix_line = lines.pop(0)
    fw_date_line = lines.pop(0)
    header_line = lines.pop(0)
    if "File Version" in file_ver_line and header_line.startswith("Mode"):
        parsed_config["file_version"] = file_ver_line
        parsed_config["firmware_prefix"] = fw_prefix_line
        parsed_config["firmware_date"] = fw_date_line
    else:
        log.warning("Unknown Woodward .tc format")
        return {}

    parsed_config["config"] = {}
    for line in lines:
        fields = line.split("\t")
        if not len(fields) == 9:
            log.debug(f"Malformed line: '{line}'")
            bad_lines += 1
            continue

        # Build Mode, Category, Block Name, and Field Name organization,
        # then populate with Type, Current, Initial, Low, and High
        ref = parsed_config["config"]
        # Walk through each layer of the organization
        for n in range(4):
            if fields[n] not in ref:
                ref[fields[n]] = {}  # create a new layer if necessary
            ref = ref[fields[n]]  # walk to the next layer
        # Now populate the top layer
        ref["Type"] = fields[4]
        ref["Current"] = fields[5]
        ref["Initial"] = fields[6]
        ref["Low"] = fields[7]
        ref["High"] = fields[8]

    if bad_lines > 0:
        log.warning(f"Skipped {bad_lines} malformed lines")

    return parsed_config


__all__ = ["_parse_tc_file"]
