import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile

from peat import DeviceData, log, utils
from peat.data.models import Event


def get_info_firmware(
    dev: DeviceData,
    filepath: Path,
    timestamp: datetime | None = None,
) -> bool:
    """
    Extract general info from firmware file.

    - Hashes
    - System architecture
    - OS version
    """
    log.info(f"Attempting to obtain information from device firmware '{filepath.name}'")

    try:
        fstat = filepath.stat()

        remote_path = filepath.as_posix().replace(dev.get_out_dir().as_posix(), "")
        remote_path = PurePosixPath(remote_path)

        if not timestamp:
            # NOTE: this assumes PEAT is not being run from a FAT-formatted filesystem
            # FAT formatted filesystems Windows uses local times for file timestamps
            # Unix filesystems and NTFS use UTC.
            timestamp = datetime.fromtimestamp(fstat.st_mtime, tz=UTC)

        with filepath.open("rb") as file:
            original_img = file.read()  # get original file as bytes

            hashes = utils.gen_hashes(original_img)
            dev.firmware.file.hash.md5 = hashes["md5"]
            dev.firmware.file.hash.sha256 = hashes["sha256"]

            # store firmware
            dev.firmware.original = original_img
            dev.firmware.timestamp = timestamp

            dev.firmware.file.name = filepath.name
            dev.firmware.file.path = remote_path
            dev.firmware.file.size = fstat.st_size
            dev.firmware.file.type = "file"
            dev.firmware.file.directory = remote_path.parent.as_posix()
            dev.firmware.file.mtime = timestamp
            dev.firmware.file.local_path = filepath

            file.seek(0)  # reset head

            elffile = ELFFile(file)  # used to read data from ELF binary

            # get system architecture
            dev.architecture = elffile.get_machine_arch()

            # get OS info
            # This section was adapted from the "readelf.py"
            # script provided by pyelftool developers and
            # located at: https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py

            section = elffile.get_section_by_name(".text")
            isSection = True
            if section is None or section["sh_type"] == "SHT_NOBITS":
                isSection = False

            found = False
            data1 = section.data()
            dataptr = 0

            while dataptr < len(data1) and isSection:
                while dataptr < len(data1) and not (32 <= data1[dataptr] <= 127):
                    dataptr += 1

                if dataptr >= len(data1):
                    break

                endptr = dataptr
                while endptr < len(data1) and data1[endptr] != 0:
                    endptr += 1

                found = True
                newString = bytes2str(data1[dataptr:endptr])

                # Check if file contains VxWorks OS info
                res = re.match(r"VxWorks\s?(\d+[\d\.]*)", newString)
                if res:
                    dev.os.name = "VxWorks"
                    dev.os.version = res.groups()[0]

                dataptr = endptr

            if found:
                log.info("Successfully pulled info from firmware file")
                return True

            log.warning("Could not find OS information on device")
    except FileNotFoundError as fnf:
        log.warning(f"Error processing Firmware file (VxWorks.st): {fnf}")

    return False


def get_info_bootrom(dev: DeviceData, filepath: Path, timestamp: datetime | None = None) -> bool:
    """
    Extract general info from bootrom file.
    """
    log.info(f"Attempting to obtain information from device boot firmware '{filepath.name}'")

    try:
        fstat = filepath.stat()
        original_img = filepath.read_bytes()  # get original file as bytes
    except Exception as ex:
        log.warning(f"Error processing bootrom Firmware file '{filepath}': {ex}")
        return False

    if not timestamp:
        # NOTE: this assumes PEAT is not being run from a FAT-formatted filesystem
        # FAT formatted filesystems Windows uses local times for file timestamps
        # Unix filesystems and NTFS use UTC.
        timestamp = datetime.fromtimestamp(fstat.st_mtime, tz=UTC)

    remote_path = filepath.as_posix().replace(dev.get_out_dir().as_posix(), "")
    remote_path = PurePosixPath(remote_path)

    hashes = utils.gen_hashes(original_img)  # get hashes of file
    dev.boot_firmware.file.hash.md5 = hashes["md5"]
    dev.boot_firmware.file.hash.sha256 = hashes["sha256"]

    # store boot firmware data
    dev.boot_firmware.original = original_img
    dev.boot_firmware.timestamp = timestamp

    dev.boot_firmware.file.path = remote_path
    dev.boot_firmware.file.directory = remote_path.parent.as_posix()
    dev.boot_firmware.file.size = fstat.st_size
    dev.boot_firmware.file.type = "file"
    dev.boot_firmware.file.name = filepath.name
    dev.boot_firmware.file.mtime = timestamp
    dev.boot_firmware.file.local_path = dev.get_out_dir() / remote_path

    return True


def parse_log(dev: DeviceData, filepath: Path) -> bool:
    """
    Parse ``Log.txt``.
    """
    # TODO sometimes file just has one line, check for this and
    # figure out why its empty sometimes, maybe tell main micronet
    # code to try re-downloading it if empty (return false -> retry dl?)

    # TODO: add log.file.* fields to event data model to store info
    # about log file on the device

    log.info(f"Attempting to extract data from log file '{filepath}'")

    try:
        data = filepath.read_text()
        file_lines = data.strip().splitlines()
        if not file_lines:  # check if log file actually has content
            log.warning(f"Unable to parse events from '{filepath}' - Empty Log File")
            return False
    except Exception as ex:
        log.warning(f"Error processing log file '{filepath}': {ex}")
        return False

    start_times = []
    # get date/time info and store as datetime obj
    if "VxWorks:Started" in file_lines[1]:
        start_info = file_lines[1].split()
        start_info_date = start_info[2].split("/")
        start_info_time = start_info[3].split(":")
        start_time = datetime(
            year=int(start_info_date[0]),
            month=int(start_info_date[1]),
            day=int(start_info_date[2]),
            hour=int(start_info_time[0]),
            minute=int(start_info_time[1]),
            second=int(start_info_time[2]),
        )
        start_times.append(start_time)
        # remove filename and date/time info, everything after is events
        file_lines.pop(0)
        file_lines.pop(0)

        # log start time
        dev.start_time = start_times[-1]

    # get every line and process as new event
    events = []
    start_times = []  # use this to get most recent start time
    for line in file_lines:
        if "VxWorks:Started" in line:  # if this event is a start time, log separately
            start_times.append(line)
        else:
            if line != "":
                line_split = line.split(" - ")
                action_message = line_split[0].split(":")
                time = datetime.strptime(line_split[-1][:-1], "%Y/%m/%d %H:%M:%S")

                # some events don't contain a message,
                # this check accounts for that
                if action_message[1] != "":
                    # create a new event for each line in log
                    new_event = Event(
                        action=action_message[0],
                        dataset=filepath.name,
                        message=action_message[1],
                        original=line,
                        created=time,
                    )
                    events.append(new_event)
                else:
                    new_event = Event(
                        action=line_split[0],
                        dataset=filepath.name,
                        message="none",
                        original=line,
                        created=time,
                    )
                    events.append(new_event)

    for event in events:
        dev.event.append(event)

    if events:
        get_ip_addrs(dev, events)

    return True


def get_ip_addrs(dev: DeviceData, events: list[Event]) -> None:
    """
    Get IP addresses from the log file and store them in data manager.
    """
    log.info("Extracting IP addresses from log")
    for event in events:
        if "Setting unit" in event.message:
            # There's an event setting broadcast addresses
            # Log these IP addresses
            new_ip = event.message.split()[-1]
            if new_ip not in dev.related.ip:  # avoid duplicates
                dev.related.ip.add(new_ip)


def get_gap_info(dev: DeviceData, filename: str, path: Path, timestamp: datetime) -> bool:
    """
    Get info on gap file ``*gaprev*.out``.
    """
    log.info(f"Attempting to obtain information from device gap file '{filename}'")

    try:
        filepath = path
        file_size = filepath.stat().st_size
        original_img = filepath.read_bytes()  # get original file as bytes
    except Exception as ex:
        log.warning(f"Error processing GAP file '{filename}': {ex}")
        return False

    remote_path = filepath.as_posix().replace(dev.get_out_dir().as_posix(), "")
    remote_path = PurePosixPath(remote_path)

    if not dev.logic.name:
        dev.logic.name = "GAP file"

    dev.logic.original = str(original_img)

    hashes = utils.gen_hashes(original_img)  # get hashes of file
    dev.logic.file.hash.md5 = hashes["md5"]
    dev.logic.file.hash.sha1 = hashes["sha1"]
    dev.logic.file.hash.sha256 = hashes["sha256"]
    dev.logic.file.hash.sha512 = hashes["sha512"]

    dev.logic.file.device = "MicroNet Plus"
    dev.logic.file.path = remote_path
    dev.logic.file.directory = remote_path.parent.as_posix()
    dev.logic.file.name = filename
    dev.logic.file.local_path = dev.get_out_dir() / remote_path
    dev.logic.file.size = file_size
    dev.logic.file.type = "file"
    dev.logic.file.extension = "out"
    dev.logic.file.size = file_size
    dev.logic.file.mtime = timestamp

    if not dev.logic.last_updated:
        dev.logic.last_updated = timestamp

    return True


def create_artifact(dev: DeviceData, filepath: Path, timestamp: str) -> None:
    """
    Get hashes of each file pulled and store each as dict
    with fields ``filename``, ``md5``, ``sha256``.

    Each of these is stored in ``dev.extra["file_artifacts"]``.
    """
    remote_path = filepath.as_posix().replace(dev.get_out_dir().as_posix(), "")
    try:
        new_artifact = {
            "filename": filepath.name,
            **utils.gen_hashes(filepath),
            "filepath": filepath,
            "timestamp": timestamp,
            "path": PurePosixPath(remote_path, filepath.name),
            "local_path": filepath.as_posix(),
        }

        if not dev.extra.get("file_artifacts"):
            dev.extra["file_artifacts"] = []
        dev.extra["file_artifacts"].append(new_artifact)
    except FileNotFoundError as fnf:
        log.warning(f"Error generating file artifact: {fnf}")
