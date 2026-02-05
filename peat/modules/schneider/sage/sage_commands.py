"""
Sage-specific command query and parsing.

Useful doc for understanding some command outputs:

- https://www.cisco.com/en/US/docs/wireless/access_point/350/configuration/guide/ap35ch13_ps458_TSD_Products_Configuration_Guide_Chapter.html
- https://docstore.mik.ua/univercd/cc/td/doc/product/wanbu/mgx8260/rel1_2/maint/mainb.htm
- https://github.com/bousqi/SMEG_PLUS/blob/master/VXWORKS.md

Authors

- Aaron Lombrozo
- Christopher Goes
- Kevin Cox
"""

import binascii
import re
import string
import time
from typing import Any

from peat import DeviceData, DeviceError, ParseError, config, consts, log, state, utils
from peat.data.models import User

from . import sage_parse


class SageCommands:
    """
    Sage-specific device commands and parsing.

    This class maintains the Sage device commands and command parsing.
    It's intended to be inherited, and not meant to be used directly.
    """

    TYPE: str = ""  # Overridden by subclasses. Lowercase string.

    def _query(self, command: str, prompt_str: str) -> str:
        self.write(command)

        if command == "i":
            read_until_str = "Type <CR> to continue, Q<CR> to stop:"
            response = self.read_until(read_until_str).strip()

            # Get rid of the type continue issue.
            if "Type <CR>" in response:
                add_response = self.query("")
                while "Type <CR>" in add_response:
                    add_response = add_response.replace(
                        "Type <CR> to continue, Q<CR> to stop:", ""
                    )
                    add_response = add_response + self.query("")

                # Strip out the CR from original response.
                response = response.replace("Type <CR> to continue, Q<CR> to stop:", "")
                response += add_response
        else:
            response = self.read_until(prompt_str).strip()

        # strip command off front of response
        if response.startswith(command):
            response = response[len(command) :].lstrip()

        # strip prompt from end of response
        if response.endswith(prompt_str.strip()):
            response = response[: -len(prompt_str.strip())].strip()

        # set directory for responses if unset
        if not self.resp_dir and self.dev and config.DEVICE_DIR:
            self.resp_dir = self.dev.get_sub_dir(f"{self.TYPE}_responses")

        # Save raw response to a file
        if response and self.resp_dir:
            ts = utils.utc_now().strftime(consts.TIME_FMT)
            filename = f"{command.replace(' ', '_')}_{ts}.txt"
            filename = filename.replace(",", "-")  # remove commas

            if command.split(" ", maxsplit=1)[0] in ["d", "ti"]:
                file_path = self.resp_dir / "task_responses" / filename
            else:
                file_path = self.resp_dir / filename

            utils.write_file(response, file_path)

        return response

    def query(self, command: str) -> str:
        """
        Query the Sage device with the given command.

        This includes a write, followed by a read.
        The prompt for this interface is ``->``.

        Args:
            command: The command to run.

        Returns:
            str: The Sage device response.
        """
        return self._query(command, "->")

    def cmd_query(self, command: str) -> str:
        """
        Query the Sage device in the 'cmd' interface state.

        The prompt for this interface is ``[vxWorks]#``.
        This state is entered into by running the ``cmd`` command.

        Args:
            command: The command to run.

        Returns:
            str: The sage device response.
        """
        return self._query(command, "[vxWorks]# ")

    def get_tasks(self) -> dict[str, Any]:
        """
        Get tasks by running ``checkStack`` command, save the output
        to a file, and parse the output and return as a dict.
        """
        check_stack_response = self.query("checkStack")
        if not check_stack_response:
            raise DeviceError(f"No output from checkStack on {self.dev.ip}")

        # Save raw task list to disk
        self.dev.write_file(check_stack_response, "task-list.txt")

        # parse into TID-indexed dictionary (TID = Task ID, as hex)
        tasks = parse_check_stack_response(check_stack_response)
        return tasks

    def query_update_task_entry(self, tasks: dict[str, Any]) -> None:
        """
        Query appropriate tasks to get the full entry point alias. The response is
        added to the input tasks dict (modified in-place).

        Args:
            tasks: Dictionary containing tasks.
        """
        invalid_tasks = []
        for task_id, t_dict in tasks.items():
            ti_response = self.query(f"ti {task_id}")

            # This mutates t_dict in-place
            parse_success = parse_ti_response(ti_response, t_dict)

            if not parse_success:
                # ti response was invalid, remove entry
                self.log.debug(
                    f"{t_dict['NAME']} is no longer valid and will be removed"
                )
                invalid_tasks.append(task_id)

        # Can't mutate the dict in place while iterating
        for task_id in invalid_tasks:
            tasks.pop(task_id)

    def query_read_memory_from_tasks(self, tasks: dict[str, Any]) -> None:
        """
        Query and update the read memory from the given task mapping. The memory read
        duration is added to understand length of time for response.

        The tasks dict is modified in-place.

        Args:
            tasks: Dictionary containing tasks.
        """
        self.log.info(f"Reading {len(tasks)} tasks from {self.dev.ip}")

        for t_dict in tasks.values():
            if t_dict["d_query_duplicate"] == "":
                start_read_time = time.time()
                memory_read_time = utils.utc_now()

                t_dict["d_response"] = self.query(t_dict["d_query"])

                read_time_duration = time.time() - start_read_time
                t_dict["memory_read_time"] = memory_read_time

                # Add debug log for memory read_time_duration
                self.log.debug(
                    f'{t_dict["NAME"]} took {read_time_duration:.2f} '
                    f'seconds for {t_dict["SIZE"]} bytes'
                )


def parse_ti_response(ti_response: str, tid_dict: dict[str, Any]) -> bool:
    """
    Parse the Sage device ti command response.

    Parse result of ``ti`` query to update the ENTRY point,
    or mark for later deletion if no longer found.

    Args:
        ti_response: Sage device ti command response
        tid_dict: Sage device TID mappings

    Returns:
        True if the task was found, False if not.
    """
    if not ti_response:
        log.warning(
            f"Empty output from 'ti' command for task "
            f"{tid_dict.get('NAME', 'unknown')}"
        )
        return False

    # remove the task because it no longer exists...
    if "task not found" in ti_response:
        log.debug(
            f"Task {tid_dict.get('NAME', 'unknown')} will be removed "
            f"because it no longer exists"
        )
        return False

    # NAME  ENTRY TID  PRI   STATUS   PC    SP   ERRNO  DELAY
    # STATUS: READY, PEND, DELAY, SUSPEND, and a few others
    ti_lines = _extract_lines(ti_response)
    column_names = ti_lines[0].split()
    vals = ti_lines[2].split()
    for key, val in zip(column_names, vals, strict=False):
        if key not in tid_dict:
            tid_dict[key] = val

    for line in ti_lines[4:]:
        if line.startswith("task entry "):
            # update ENTRY point and add formatted memory read command
            # check to see if the entry evaluated to a longer string
            task_entry = line.split(":")[-1].strip()  # "mudThread"
            if tid_dict["ENTRY"] != task_entry and "0x" not in tid_dict["ENTRY"]:
                # update 'ENTRY' with longer string from 'task entry'
                log.debug(f"{tid_dict['ENTRY']} is now {task_entry}")
                tid_dict["ENTRY"] = task_entry
        elif line.startswith("process "):
            # process        : kernel
            tid_dict["PROCESS"] = line.split(":")[-1].strip()
        elif line.startswith("options "):
            # process        : kernel
            tid_dict["OPTIONS"] = line.split(":")[-1].strip()

    # Generate commands for reading memory: d ENTRY,NUMBER OF CHUNKS,WIDTH OF CHUNK
    size = int(int(tid_dict["SIZE"]) / 8)
    tid_dict["d_query"] = f"d {tid_dict['ENTRY']},{size},8"

    return True


def parse_check_stack_response(check_stack_response: str) -> dict[str, Any]:
    """
    Parse the ``checkStack`` command output to create the initial task dictionary.

    Args:
        check_stack_response: Sage output for ``checkStack`` command

    Returns:
        tasks: Parsed tasks from checkStack
    """
    check_stack_lines = _extract_lines(check_stack_response)
    if not check_stack_lines:
        log.error("Empty checkStack response")
        return {}

    if "NAME" not in check_stack_lines[0]:
        log.error("Failed to parse header from checkStack command")
        state.error = True
        return {}

    # List of column names, e.g. "NAME", "SIZE", etc.
    # NAME        ENTRY        TID       SIZE   CUR  HIGH  MARGIN
    column_names = check_stack_lines[0].split()

    # This is where the initial keys are set
    # for the tasks dict, such as "SIZE".
    # These are created from the header of the output.
    tasks = {}
    for task_row in check_stack_lines[2:]:
        if "0x" in task_row:
            tid_dict = {}
            for index, col_name in enumerate(column_names):
                tid_dict[col_name] = task_row.split()[index]
            tasks[tid_dict["TID"]] = tid_dict
        elif "INTERRUPT" in task_row:
            break

    log.info(f"Detected {len(tasks)} tasks at {utils.time_now()}")
    return tasks


def mark_duplicate_tasks(tasks: dict[str, Any]) -> None:
    """
    Mark the tasks as duplicate if duplicates exist.

    Some commands are duplicates. No need to re-read the same memory.
    Mark duplicates with TID references to skip and fill in later.

    This mutates the tasks dict in-place.

    Args:
        tasks: Parsed tasks from checkStack
    """
    d_query_list = []
    tid_list = []

    for t_dict in tasks.values():
        if t_dict["d_query"] in d_query_list:
            t_dict["d_query_duplicate"] = tid_list[
                d_query_list.index(t_dict["d_query"])
            ]
            log.debug(
                f"{t_dict['NAME']} uses {t_dict['ENTRY']} which is a duplicate of "
                f"{tasks[tid_list[d_query_list.index(t_dict['d_query'])]]['NAME']}"
            )
        else:
            t_dict["d_query_duplicate"] = ""

        d_query_list.append(t_dict["d_query"])
        tid_list.append(t_dict["TID"])


def find_duplicate_memory_reads(tasks: dict[str, Any]) -> None:
    """
    Fill in duplicate (shared) memory queries that were previously skipped.

    This mutates the tasks dict in-place.

    Args:
        tasks: Parsed tasks from checkStack
    """
    for t_dict in tasks.values():
        if t_dict["d_query_duplicate"] != "":
            t_dict["d_response"] = tasks[t_dict["d_query_duplicate"]]["d_response"]
            t_dict["memory_read_time"] = tasks[t_dict["d_query_duplicate"]][
                "memory_read_time"
            ]


def convert_memory_reads_to_hex_strings(tasks: dict[str, Any]) -> None:
    """
    Convert memory reads into hex strings and bytes.

    This adds values to tasks in-place, and does NOT make a copy.

    Args:
        tasks: Parsed tasks from checkStack
    """
    for task_id, t_dict in tasks.items():
        try:
            t_dict["memory_hex"] = convert_memory_read_to_hex_string(
                t_dict["d_response"]
            )
        except ParseError as ex:
            t_dict["memory_hex"] = ""
            t_dict["memory_bytes"] = b""
            log.error(f"Error converting hex for task id '{task_id}': {ex}")
            return

        try:
            t_dict["memory_bytes"] = binascii.unhexlify(t_dict["memory_hex"])
        except Exception as ex:
            log.error(f"Failed to convert hex to bytes for task ID '{task_id}': {ex}")
            t_dict["memory_bytes"] = b""


def convert_memory_read_to_hex_string(d_response: str) -> str:
    """
    Convert the stored memory reads to hex string.

    Args:
        d_response: Stored memory read.

    Returns:
        str: Memory reads converted to hex string.
    """
    hex_memory_list = []

    for line in d_response.splitlines():
        if "0x" not in line:
            continue
        chunks = line.split()
        for chunk in chunks:
            if len(chunk) == 16 and "*" not in chunk and "." not in chunk:
                hex_memory_list.append(chunk)

    hex_string = "".join(hex_memory_list)

    if not all(c in string.hexdigits for c in hex_string):
        bad = {}  # type: dict[str, str]
        for i, c in enumerate(hex_string):
            if c not in string.hexdigits:
                bad[str(i)] = c
        raise ParseError(
            f"Bad characters in hex string: {''.join(bad.keys())} "
            f"(positions: {list(bad.values())})"
        )

    return hex_string


def save_memory_reads_to_disk(dev: DeviceData, tasks: dict[str, Any]) -> None:
    """
    Save the stored task memory reads to files on disk.

    There are several formats each read is saved to, in separate sub-directories
    under the ``memory_reads/`` directory.

    These are:

    - ``ascii/*.txt`` : ASCII strings from the hexdump output
    - ``hexdump/*.txt`` : Hexdump-format output from VxWorks "ti" command
    - ``hex/*.hex``: Lowercase Hexadecimal string
    - ``binary/*.bin``: binary format. This is the hex values
        converted to raw binary data and written to a file.

    Args:
        dev: DeviceData object to use for saving
        tasks: Parsed tasks from checkStack
    """
    for t_dict in tasks.values():
        task_str = f'{t_dict["NAME"]}-{t_dict["TID"]}'.replace(":", "")
        mem_dir = dev.get_sub_dir("memory_reads")

        # "Hexdump"-style format from the response
        # Ignore everything before first "0x",
        # and ignore "value = 0 = 0x0" at the end
        hexdump_temp = "0x" + t_dict["d_response"].partition("0x")[2]
        hexdump = hexdump_temp.rpartition("value = ")[0].strip()
        # avoid issue where hexdump is empty due to
        # unexpected formatting difference with the line above
        if not hexdump:
            hexdump = hexdump_temp

        # try to remove blank lines that sometimes happen
        hexdump = hexdump.replace("\r\n\r\n", "\r\n")
        hexdump = hexdump.replace("\n\n", "\n")

        dev.write_file(
            data=hexdump,
            filename=f"{task_str}.txt",
            out_dir=mem_dir / "hexdump",
        )

        # Pull out just the strings from the "hexdump" format
        strings = "".join(re.findall(r"\*(.+)\*", hexdump, re.ASCII))
        dev.write_file(
            data=strings,
            filename=f"{task_str}.txt",
            out_dir=mem_dir / "ascii",
        )

        # Hexadecimal format (pure hex, not hex + ASCII)
        dev.write_file(
            data=t_dict["memory_hex"],
            filename=f"{task_str}.hex",
            out_dir=mem_dir / "hex",
        )

        # Binary format
        dev.write_file(
            data=t_dict["memory_bytes"],
            filename=f"{task_str}.bin",
            out_dir=mem_dir / "binary",
        )

    log.info(f"Saved memory reads to disk for {len(tasks)} tasks from {dev.ip}")


def parse_vxworks_version(data: str) -> dict[str, str]:
    """
    Parse the output of the ``version`` command in the VxWorks "C" interpreter,
    and extract the version of VxWorks.

    Extracted information:

    - vxworks_version
    - wind_version
    - timestamp
    - raw_bootline
    - ata
    - host
    - ethernet_ip
    - ethernet_subnet_mask
    - host_ip
    - gateway_ip
    - flags
    - target_name
    - other

    Args:
        data: Command output to parse

    Returns:
        Extracted information as a dictionary, or an empty dict if the
        parse failed.
    """
    # Information about Kernel version
    #
    # https://www.ecb.torontomu.ca/~courses/ee8205/Data-Sheets/Tornado-VxWorks/vxworks/ref/kernelLib.html
    #
    # "This routine returns a string which contains the current revision of
    # the kernel. The string is of the form "WIND version x.y", where "x"
    # corresponds to the kernel major revision, and "y" corresponds to the
    # kernel minor revision."

    regex = (
        r"\s*VxWorks.* version (?P<vxworks_version>\d[\d\.]*\d)\.?"
        r"\s*.*WIND version (?P<wind_version>\d[\d\.]*\d)\.?"
        r"\s*.*Made on (?P<timestamp>\w+\s+\d+\s+\d+[\s,]+\d+\:\d+\:\d+)\.?"
        r"\s*Boot line\:\s+(?P<raw_bootline>.*)"
    )  # type: str

    match = re.match(regex, data, re.IGNORECASE | re.ASCII)

    if not match:
        return {}

    regex_results = match.groupdict()
    results = {}

    for key in list(regex_results.keys()):
        if regex_results[key] is not None:
            results[key] = regex_results[key].strip().strip(".")

            # leverage existing bootline parser from sage_parse
            if key == "raw_bootline":
                results.update(sage_parse.bootline_parse(regex_results[key]))
        else:
            results[key] = ""

    return results


def process_vxworks_version(data: dict[str, str], dev: DeviceData) -> None:
    """
    Process data from parsed output of VxWorks ``version``
    command into the PEAT device data model.

    Args:
        data: version data parsed by ``parse_vxworks_version()``
    """
    if data.get("vxworks_version"):
        dev.os.version = data["vxworks_version"]

    if data.get("wind_version"):
        dev.os.kernel = data["wind_version"]

    if data.get("timestamp"):
        ts = utils.parse_date(data["timestamp"])
        if ts:
            dev.os.timestamp = ts

    sage_parse.process_bootline(dev, data)


def parse_sysvar_list(data: str) -> dict[str, str]:
    """
    Parse output of ``sysvar list`` command on the Sage.
    """
    lines = _extract_lines(data)
    if not lines:
        return {}

    variables = {}

    for line in lines[1:]:
        key, _, value = line.partition("=")
        variables[key] = value

    return variables


def process_sysvar_list(variables: dict, dev: DeviceData) -> None:
    """
    Process output of ``sysvar list`` command on the Sage.
    """
    if not variables:
        return

    # TODO: do more with the values in here?
    variables = utils.sort(variables)
    dev.extra["system_variables"] = variables

    for key, value in variables.items():
        if ".user" in key or ".username" in key:
            dev.related.user.add(value)


def parse_user_list(data: str) -> list[dict[str, str]]:
    """
    Parse output of ``user list`` command on the Sage.
    """
    users = []

    for line in _extract_lines(data, exclude="Users:"):
        # "1   Admin"
        parts = [x.strip() for x in line.split(" ") if x.strip()]
        user = {"num": parts[0], "name": parts[1]}
        users.append(user)

    return users


def process_user_list(users: list[dict[str, str]], dev: DeviceData) -> None:
    """
    Process output of ``user list`` command on the Sage.
    """
    for user_dict in users:
        user_obj = User(name=user_dict["name"])
        dev.store("users", user_obj, lookup="name")
        dev.related.user.add(user_dict["name"])


def parse_ipf(data: str) -> dict:
    lines = _extract_lines(data, exclude="FIREWALL STATISTICS:")
    if not lines:
        return {}

    fw_stats = {}

    for line in lines[1:]:
        if line.count(":") != 1:
            continue

        key, _, value = line.partition(":")
        key = "_".join(x for x in key.split(" ") if x.strip())
        value = value.strip()

        try:
            fw_stats[key] = int(value)
        except Exception:
            fw_stats[key] = {}
            parts = value.split(" ")
            for k, v in zip(parts[0::2], parts[1::2], strict=False):
                fw_stats[key][k] = int(v)

    return fw_stats


def _extract_lines(data: str, exclude: str = "") -> list[str]:
    if not data:
        return []

    lines = []

    for line in data.strip().splitlines():
        line = line.strip()
        if not line or (exclude and exclude in line):
            continue
        lines.append(line)

    return lines
