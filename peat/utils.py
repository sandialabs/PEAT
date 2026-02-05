import atexit
import functools
import hashlib
import importlib.resources
import json
import locale
import os
import re
import shutil
import site
import sys
from collections.abc import Container, Iterable
from contextlib import ExitStack
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from traceback import format_exc
from typing import Any

import pathvalidate
from dateutil.parser import parse as date_parse
from humanfriendly import format_size, format_timespan

from peat import config, log, state
from peat.protocols.common import MAC_RE_COLON

from . import consts
from .consts import SYSINFO


def convert_to_snake_case(camel_string: str) -> str:
    """
    Converts a string from CamelCase to snake_case.
    """
    camel_string = camel_string.strip()
    if not camel_string:
        return ""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", camel_string)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.lower()


def clean_replace(to_clean: str, replace_with: str, chars: str) -> str:
    clean = to_clean.strip().lower()
    for char in chars:
        clean = clean.replace(char, replace_with)
    return clean


def clean_empty_dirs(to_clean: Path) -> None:
    """
    Recursively remove all empty directories on the path.
    """
    try:
        listing = list(to_clean.iterdir())
        if not listing:
            to_clean.rmdir()
        else:
            for item in listing:
                if item.is_dir():
                    clean_empty_dirs(item)
    except OSError:
        pass


def fmt_duration(seconds: int | float | timedelta) -> str:
    """
    Format a time duration into a human-readable string.

    Wrapper for ``humanfriendly.format_timespan()``.
    """
    # If greater than a minute, display the human-readable
    # durations + total seconds in brackets []. Otherwise,
    # just print the formatted seconds
    if (isinstance(seconds, timedelta) and seconds.seconds >= 60) or (
        not isinstance(seconds, timedelta) and int(seconds) >= 60
    ):
        return (
            f"{format_timespan(seconds, detailed=False, max_units=10)}"
            f" [{seconds:.2f} seconds]"
        )
    else:
        return format_timespan(seconds, detailed=False, max_units=10)


def fmt_size(size_in_bytes: int) -> str:
    """
    Convert a integer size into a human-readable string.

    Wrapper for ``humanfriendly.format_size()``.
    """
    return f"{format_size(size_in_bytes)} [{size_in_bytes} bytes]"


def sort(obj: dict) -> dict:
    """
    Sort a dictionary. Returns a new dict (it doesn't sort in-place).
    """
    return dict(sorted(obj.items(), key=lambda x: str(x[0])))


def short_pth_str(path: Path, max_parts: int = 4) -> str:
    """
    Generate a string of a subset of a path.

    Args:
        path: Path to convert
        max_parts: Number of parts of the path to show, including the base.
            For example, a file path with ``max_parts=4`` will show the filename
            and 3 parent directories.
            If the number of parts is less than ``max_parts`` then the entire
            path is shown.

    Returns:
         Shortened file path string
    """
    if len(path.parts) < max_parts:
        return path.as_posix()
    else:
        return "/".join(path.parts[-max_parts:])


def move_item(obj: list, new_position: int, item: Any) -> None:
    """
    Move an item in a list to a new position in the list.
    """
    old_position = obj.index(item)
    obj.insert(new_position, obj.pop(old_position))


def move_file(src: Path, dest: Path) -> Path:
    """
    Move a file, handling duplicates and/or destination directory creation.

    If src is a file and dest is a directory, then dest will be changed to be
    the name of the src file with the original dest as the parent, following
    the behavior of the ``cp`` command.

    Returns:
        The updated path of the file
    """
    if src.is_file() and dest.is_dir():
        dest = dest.joinpath(src.name)

    if dest.exists():
        dest = dup_path(dest)  # Handle duplicates
    elif not dest.parent.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)

    src.rename(dest)
    return dest


def merge(d1: dict | None, d2: dict | None, no_copy: bool = False) -> dict:
    """
    Merges two dictionaries.

    Values in d1 take priority over d2. If one of the
    dictionaries is :class:`None`, then the other is returned.
    """
    if d1 is None and d2 is None:
        raise ValueError("Both dictionaries in a merge cannot be None")

    if d1 is None:
        return d2
    elif d2 is None:
        return d1

    if not no_copy:
        final = deepcopy(d1)
    else:
        final = d1

    for k in d2:
        if k in final:
            if isinstance(final[k], dict) and isinstance(d2[k], dict):
                merge(final[k], d2[k], no_copy=True)
        else:
            final[k] = d2[k]

    return final


def parse_date(raw_time: str, year_first: bool | None = None) -> datetime | None:
    """
    Parse a raw string into a datetime object or ISO 8601 date string.

    This leverages dateutil's fuzzy parser, which can handle a wide
    array of input time formats.

    .. warning::
       This function does not do any special timezone handling. If a timezone
       is presented, then it's included in the datetime object's ``tzinfo``,
       otherwise it's timezone-unaware. Ensure you properly convert to UTC!

    .. note::
       To get a ISO 8601-formated string, call ``.isoformat()`` on the
       returned datetime object. This will result in a string in the
       following format: ``<YYYY-MM-DD>T<HH:MM:SS.mmmmmm>``

    Args:
        raw_time: time string to parse, in almost any format (within reason)
        iso_format: If the a ISO 8601 format string should be returned
            instead of a datetime object
        year_first: Whether to interpret the first value in an ambiguous
            3-integer date (e.g. 01/05/09) as the year. Passed straight
            to dateutil.parse().

    Returns:
        :class:`datetime.datetime` object, or :obj:`None` if the parse fails.
    """
    if isinstance(raw_time, bytes):  # Handle accidental byte passing
        raw_time = raw_time.decode()

    try:
        return date_parse(raw_time.strip(), fuzzy=True, yearfirst=year_first)
    except Exception as ex:
        log.error(f"Failed to parse date string '{raw_time}': {ex}")
        return None


def get_formatted_platform_str() -> str:
    """
    Record information about the current system and environment.
    """

    runtime_info = f"""
Start time          {SYSINFO['start_time']} ({SYSINFO['timezone']})
PEAT directory      {_pth_log_string(config.OUT_DIR)}
Run directory       {_pth_log_string(config.RUN_DIR)}
PEAT Run ID         {SYSINFO['run_id']}
PEAT Entrypoint     {state.entrypoint}\n"""
    if "cli_arguments" in SYSINFO:
        runtime_info += (
            f"\nCLI arguments       {SYSINFO['cli_exe']} {SYSINFO['cli_arguments']}"
        )
    environment_info = f"""\n
Environment
    Python version      {SYSINFO['python_version']} ({SYSINFO['python_impl']} {SYSINFO['arch']})
    Python executable   {SYSINFO['python_exe']}
    Current directory   {Path.cwd().as_posix()}
    tcpdump path        {SYSINFO['tcpdump']}
    Process ID          {SYSINFO['pid']}\n"""
    system_info = f"""
System
    Hostname       {SYSINFO['hostname']}
    Username       {SYSINFO['username']}
    OS             {SYSINFO['os_full']}
    CPU            {SYSINFO['cpu']}
    Containerized  {SYSINFO['containerized']}
    Podman         {SYSINFO['podman']}\n"""
    if config.OUT_DIR and config.OUT_DIR.parent.exists():
        disk_stats = shutil.disk_usage(config.OUT_DIR.parent.as_posix())
        disk_info = f"""    Disk space (disk where OUT_DIR is configured)
        Total   {fmt_size(disk_stats.total)}
        Used    {fmt_size(disk_stats.used)}
        Free    {fmt_size(disk_stats.free)}\n"""
        system_info += disk_info
    out_dirs = f"""
Output directories (full list in the state JSON dump)
    Device results   {_pth_log_string(config.DEVICE_DIR)}
    Elastic pushes   {_pth_log_string(config.ELASTIC_DIR)}
    PEAT Logs        {_pth_log_string(config.LOG_DIR)}
    PEAT Metadata    {_pth_log_string(config.META_DIR)}
    Result summaries {_pth_log_string(config.SUMMARIES_DIR)}
    Temporary files  {_pth_log_string(config.TEMP_DIR)}
    HEAT Artifacts   {_pth_log_string(config.HEAT_ARTIFACTS_DIR)}\n\n"""
    return runtime_info + environment_info + system_info + out_dirs


def _pth_log_string(pth: Path | None) -> str:
    return pth.as_posix() if pth else "UNSET"


def get_debug_string() -> str:
    try:
        ts = shutil.get_terminal_size()
        loc = locale.getlocale()
        return f"""DEBUG INFO
    Terminal size          {ts.columns} columns, {ts.lines} lines
    Locale                 {loc if loc[0] else locale.getdefaultlocale()}
    Filesystem encoding    {sys.getfilesystemencoding()}
    sys.path               {sys.path}
    User site-packages     {site.getusersitepackages() if hasattr(site, 'getusersitepackages') else ''}
    Global site-packages   {site.getsitepackages() if hasattr(site, 'getsitepackages') else ''}
    Environ keys           {list(dict(os.environ).keys())}
    PATH                   {os.environ.get('PATH')}\n\n"""  # noqa: E501
    except Exception as ex:
        log.exception(f"Failed to generate debug info: {ex}")
        return ""


def get_resource(package: str, file: str) -> str:
    """
    Unpack and return the path to a resource included with PEAT.

    Some examples of these are schemas and definitions for :term:`TC6` XML.

    The resources are unpacked into a temporary directory.
    These temporary files are cleaned up when PEAT exits.

    Details: https://importlib-resources.readthedocs.io/en/latest/migration.html

    Args:
        package: where the resource is located (use ``__package__`` for this)
        file: name of the resource to get

    Returns:
        Absolute path to the resource on the filesystem
    """
    file_manager = ExitStack()
    atexit.register(file_manager.close)
    path = str(file_manager.enter_context(importlib.resources.path(package, file)))

    if not os.path.exists(path):
        state.error = True
        raise FileNotFoundError(
            f"Resource does not exist at path '{path}' "
            f"(package: '{package}', file: '{file}')"
        )

    return path


def collect_files(path: Path, sub_dirs: bool = True) -> list[str]:
    """
    Convert a path into a list of absolute file path strings.

    If path is a file, then the returned list will only contain that file.

    Args:
        path: path a file or a directory to search
        sub_dirs: if sub-directories of a directory path should be searched

    Returns:
        Absolute file paths of all files in the path,
        in the order they were listed by the OS (no sorting)
    """
    all_files: list[str] = []
    path = Path(os.path.realpath(os.path.expanduser(path)))

    if path.is_dir():
        if sub_dirs:  # Recursively walk the directory tree
            for root, _, filenames in os.walk(str(path)):
                for filename in filenames:
                    all_files.append(os.path.join(root, filename))
        else:
            for x in path.iterdir():
                if x.is_file():
                    all_files.append(str(x.resolve()))
    else:  # Single file
        all_files.append(str(path))

    return all_files


def copy_file(src_path: Path, dst_path: Path, overwrite: bool = False) -> None:
    """
    Copy and/or rename a file.
    """

    if dst_path.exists() and dst_path.samefile(src_path):
        log.debug(
            f"Skipping copying of {src_path.name} to "
            f"{dst_path.parent.name}, it's the same file"
        )
    elif (
        not overwrite
        and dst_path.exists()
        and calc_hash(src_path) != calc_hash(dst_path)
    ):
        incremented_path = dup_path(dst_path)
        log.warning(
            f"Destination file '{str(dst_path)}' exists and has a "
            f"different hash than '{str(src_path)}'. Copying to "
            f"'{incremented_path.name}' instead."
        )

        shutil.copy2(str(src_path), str(incremented_path))
        state.written_files.add(incremented_path.as_posix())
    else:
        log.debug(f"Copying file {src_path.name} to directory {dst_path.parent.name}")
        if not dst_path.parent.exists():
            dst_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(str(src_path), str(dst_path))
        state.written_files.add(dst_path.as_posix())


def check_file(file: Path | str, ext: list | str | None = None) -> str | Path | None:
    """
    Checks if a path exists and is valid, and returns the :class:`~pathlib.Path` to it.

    Args:
        file: Path to validate
        ext: Expected file extension(s). If the file doesn't have any of
        the extension(s), then a warning will be issued.

    Returns:
        Absolute Path of the file
    """
    if file is None:
        log.critical("'None' passed as 'file' argument to utils.check_file()!")
        state.error = True
        return None
    elif str(file) == "-":  # Piped input
        file = str(file)
        log.trace("Input path is from stdin")

        if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            log.error(
                "No filepath specified and input isn't from terminal (stdin). This can "
                "happen due to a issue with Python argparse. Add a '--' before the "
                "positional argument, e.g. '-d sel -- <filename>' "
                "instead of '-d sel <filename>'. If you're still "
                "having issues, please email us (peat@sandia.gov) or open an "
                "issue on GitHub."
            )
            return None
    else:  # File or directory
        # BUGFIX: Windows CLI argument of '.\stuff\things\' adds a '"'
        # character instead of a '\' if there's a tailing backslash. This
        # is often seen when using tab completion in PowerShell or CMD.
        if consts.WINDOWS and file and str(file)[-1] == '"':
            log.trace("Trimming extraneous '\"' character from path")
            file = str(file)[:-1]

        # Resolve symlinks, user vars ("~"), and make absolute
        file = Path(os.path.realpath(os.path.expanduser(file)))

        if not file.is_file() and not file.is_dir():
            log.error(f"Path doesn't exist or isn't a valid file: {file.as_posix()}")
            return None

        if isinstance(ext, str):
            ext = [ext]
        if ext and file.suffix not in ext:
            log.warning(f"Expecting a file with .{ext}, not {file.suffix}")

    return file


def fix_file_owners(to_fix: Path) -> bool:
    """
    Change owner of file(s) and directorie(s) to actual user running PEAT instead of root.
    """
    if not consts.POSIX:
        log.warning("Can't fix file owners on non-POSIX system")
        return False

    try:
        if not to_fix.exists():
            log.warning(f"Failed to fix owners of {to_fix}: path doesn't exist")
            return False

        uid = os.geteuid()
        gid = os.getegid()

        if uid == 0:
            if "SUDO_UID" not in os.environ:
                log.warning(
                    "User is root, skipping fixing of file ownership "
                    "('SUDO_UID' not in environment). "
                    "If you ran using 'sudo' and got this warning, "
                    "please report it to the PEAT team."
                )
                return False
            uid = int(os.environ["SUDO_UID"])
        if gid == 0:
            gid = int(os.environ["SUDO_GID"])

        log.info(f"Changing owners of {to_fix} to uid={uid} gid={gid}")

        if to_fix.is_file():
            shutil.chown(str(to_fix), user=uid, group=gid)
        else:
            for dirpath, _, filenames in os.walk(to_fix):
                shutil.chown(dirpath, user=uid, group=gid)
                for filename in filenames:
                    shutil.chown(os.path.join(dirpath, filename), user=uid, group=gid)

        return True
    except Exception as ex:
        log.warning(f"Failed to fix file owners for {to_fix}: {ex}")

    return False


def file_perms_to_octal(mode_string: str) -> str:
    """
    "rwxrwxr--" => "0774"
    """
    if len(mode_string) != 9:
        return ""

    # NOTE: Python 3.12 added itertools.batched(), which is far more elegant
    # for chunk in itertools.batched(mode_string, n=3)
    chunks = [mode_string[i : i + 3] for i in range(0, len(mode_string), 3)]
    str_val = "0"
    for chunk in chunks:
        val = 0
        for c in chunk:
            if c == "r":
                val += 4
            elif c == "w":
                val += 2
            elif c != "-":
                val += 1
        str_val += str(val)

    return str_val


def save_results_summary(
    data: str | bytes | bytearray | Container | Iterable,
    results_type: str,
    log_debug: bool = False,
) -> None:
    """
    Helper function to write JSON results to a file if the path is configured.
    """
    # Only save to file if the output directory is enabled in the configuration.
    if config.SUMMARIES_DIR:
        pth = config.SUMMARIES_DIR / consts.sanitize_filename(f"{results_type}.json")

        write_file(data, pth)

        if "-" in results_type:
            results_type = " ".join(results_type.split("-"))

        msg = f"Saved {results_type} to {short_pth_str(pth, 4)}"

        if log_debug:
            log.debug(msg)
        else:
            log.info(msg)


def write_temp_file(
    data: str | bytes | bytearray | Container | Iterable,
    filename: str,
) -> Path | None:
    """
    Write arbitrary data to a file in the PEAT temporary directory.

    .. note::
       The temporary directory is configured via the
       :attr:`TEMP_DIR <peat.settings.Configuration.TEMP_DIR>`
       :doc:`configuration option <configure>`
       (:attr:`config.TEMP_DIR <peat.settings.Configuration.TEMP_DIR>`).
       If this is :obj:`None`, then this function is a No-OP (it does nothing).

    Args:
        data: Data to write to the file
        filename: Name of file to write

    Returns:
        The :class:`~pathlib.Path` of the file the data was written to,
        or :obj:`None` if there was an error or
        :attr:`TEMP_DIR <peat.settings.Configuration.TEMP_DIR>`
        is disabled.
    """
    if not config.TEMP_DIR:
        log.debug(f"Skipping write of temp data '{filename}' since TEMP_DIR is None")
        return None

    f_path = config.TEMP_DIR / consts.sanitize_filepath(filename)

    try:
        if not write_file(data, f_path):
            return None
    except Exception as ex:
        log.warning(f"Failed to write temporary file data '{filename}': {ex}")
        return None

    return f_path


def write_file(
    data: str | bytes | bytearray | Container | Iterable,
    file: Path,
    overwrite_existing: bool = False,
    format_json: bool = True,
    merge_existing: bool = False,
) -> bool:
    """
    Write data to a file.

    .. warning::
       File names MUST be valid for ALL platforms, including Windows! If validation
       fails, then the name will be sanitized and changed, and therefore will
       differ from the original name passed to this function!

    .. note::
       If the file extension is ``.json``, then the data will saved as canonical
       JSON. Data will be processed into types that are JSON-compatible
       prior to conversion. Standard Python types and objects are fine.
       :class:`bytes` are decoded as UTF-8.

    .. note::
       If the containing directory/directories don't exist, they will be created
       before the file is written (same behavior as ``mkdir -p``).

    Args:
        data: Content to write to the file
        file: Path of file to write.
            This path should be an absolute path.
            Any directories on the path that don't exist will be created automatically.
            If not, it will default to the configured OUT_DIR for PEAT.
        overwrite_existing: If existing files should be overwritten
            (instead of writing to a new file with a numeric extension)
        format_json: If JSON data should be formatted with 4 space indentation
        merge_existing: If the file already exists and is JSON, then
            read the data from the existing file, merge the new data with it,
            then overwrite the file with the merged data.

    Returns:
        If the write was successful
    """
    if data is None:
        log.error(f"write_file: data is None for write to file '{str(file)}'")
        state.error = True
        return False

    # Auto-convert bytearray to bytes object so it can be written to file
    if isinstance(data, bytearray):
        data = bytes(data)

    # Check the file argument is a valid type
    if not isinstance(file, Path):
        log.critical(
            f"Invalid file argument type '{type(file).__name__}' "
            f"for file '{repr(file)}'"
        )
        state.error = True
        return False

    # Ensure file paths are absolute
    if not file.is_absolute():
        new_path = config.RUN_DIR / file.name
        log.warning(f"File path '{file}' is not absolute, changing to {new_path}")
        file = new_path.resolve()

    # Check if filename is valid on all platforms
    # This includes checks for characters that aren't allowed on Windows (e.g. , "?")
    # or Linux, as well as reserved names on Windows (e.g. "CON").
    try:
        pathvalidate.validate_filename(file.name, platform="universal")
    except pathvalidate.ValidationError as ex:
        # If not valid, create a new filename that's sanitized
        sanitized_name = consts.sanitize_filename(file.name)

        # Log the invalid name as a warning and the new filename it's being changed to
        log.warning(
            f"Filename '{file.name}' is an invalid name. "
            f"Changing name to '{sanitized_name}'. "
            f"Validation error: {ex}"
        )

        # Change file name to the sanitized name
        file = file.with_name(str(sanitized_name))

    if file.exists():
        # Sanity check. Prevents small mistakes from having significant effects.
        if file.is_dir():
            log.critical(f"write_file: '{file.name}' exists and is a directory")
            state.error = True
            return False

        if merge_existing:
            log.trace(f"Merging existing data from {file.name}")

            if ".json" not in file.suffixes:
                log.critical(f"write_file: can't merge non-JSON file for '{file.name}'")
                state.error = True
                return False

            # Convert data to JSON-friendly Python types
            data = consts.convert(data)

            existing = json.loads(file.read_text(encoding="utf-8"))

            if type(existing) is not type(data):
                log.critical(
                    f"write_file: existing data doesn't match new data for '{file.name}'"
                )
                state.error = True
                return False

            if isinstance(data, list):
                existing.extend(data)
            elif isinstance(data, dict):
                existing.update(data)
            else:
                log.critical(f"write_file: bad type for data for '{file.name}'")
                state.error = True
                return False

            data = existing
        elif not overwrite_existing:
            file = dup_path(file)
            msg = f"File {file.stem} already exists. Writing to {file.name} instead."
            if config.DEBUG:
                log.warning(msg)
            else:
                log.debug(msg)
        else:
            log.debug(f"Overwriting existing file '{file.name}'")
    elif not file.parent.exists():
        # Create the containing directory path if it doesn't exist
        file.parent.mkdir(parents=True, exist_ok=True)

    # Warn if writing to a file in the root directory
    if len(file.parts) == 2:
        log.warning(
            f"File '{file.as_posix()}' is possibly being written to "
            f"the root directory, which is probably a bug"
        )

    # Convert data into JSON-friendly types, then serialize into a string
    if ".json" in file.suffixes:
        try:
            # Convert data to JSON-friendly Python types
            data = consts.convert(data)

            if format_json:
                data = json.dumps(data, indent=4)
            else:
                data = json.dumps(data)
        except (TypeError, ValueError) as err:
            log.error(
                f"write_file: failed to serialize JSON to '{str(file)}' "
                f"from object of type {type(data).__name__}: {err}"
            )
            log.debug(f"** repr() of failed JSON object **\n{repr(data)}")
            state.error = True
            return False

    try:
        size = str(len(data))
    except Exception:
        size = "unknown"

    if config.DEBUG >= 2:
        log.trace2(f"Writing '{type(data).__name__}' data to {file} (len: {size})")

    try:
        if isinstance(data, (bytes, bytearray, memoryview)):
            file.write_bytes(data)
        else:
            # Line endings are written as-is, without any platform-specific
            # conversions happening, e.g. stop Python being helpful and
            # translating "\n" to "\r\n" when running on a Windows system.
            with file.open(mode="w", encoding="utf-8", newline="") as fp:
                fp.write(str(data))
    except Exception as ex:
        log.error(
            f"write_file: failed to write to file {file.name} with "
            f"data of type '{type(data).__name__}': {ex}"
        )
        log.debug(f"** Traceback **\n{format_exc()}")
        state.error = True
        return False

    # Add the file to the record of all files that have been written by PEAT
    state.written_files.add(file.as_posix())

    return True


def dup_path(file: Path) -> Path:
    """
    Handle duplicate files by adding a '.<num>' to the name.
    """
    ext_count = 1
    while file.with_name(f"{file.name}.{ext_count}").exists():
        ext_count += 1
    return file.with_name(f"{file.name}.{ext_count}")


def calc_hash(source: str | bytes | Path, hash_type: str = "md5") -> str:
    """
    Calculate the hash of a file, :class:`bytes`, or :class:`str`.

    Args:
        source: Data or filepath to hash
        hash_type: Hash algorithm to use. Can be any algorithm in :mod:`hashlib`.

    Returns:
        The generated hash as a uppercase string
    """
    if isinstance(source, Path):
        algo = getattr(hashlib, hash_type)()
        with source.open("rb") as fp:
            for chunk in iter(lambda: fp.read(128 * algo.block_size), b""):
                algo.update(chunk)
    else:  # bytes/str
        if isinstance(source, str):
            source = source.encode("utf-8")
        algo = getattr(hashlib, hash_type)(source)

    return algo.hexdigest().upper()


def gen_hashes(
    source: bytes | str | Path, hash_algorithms: list[str] | None = None
) -> dict[str, str]:
    """
    Generate hashes of text, :class:`bytes`, or the contents of a file.

    Args:
        source: Data to hash, either the raw data as :class:`bytes` or
            :class:`str`, or the contents read from a file (if :class:`~pathlib.Path`).
        hash_algorithms: Hash algorithms to use. If :obj:`None`, the
            value of :attr:`~peat.settings.Configuration.HASH_ALGORITHMS`
            is used.

    Returns:
        The generated hashes as a :class:`dict` keyed
          by hash name: ``{'md5': '...', 'sha1': '...', ...}``
    """
    if not hash_algorithms:
        hash_algorithms = config.HASH_ALGORITHMS

    if isinstance(source, str):
        source = source.encode("utf-8")

    return {typ: calc_hash(source, typ) for typ in hash_algorithms}


def utc_now() -> datetime:
    """
    This simple helper function ensures a proper timezone-aware
    UTC-timezone :class:`datetime.datetime` object is returned.

    Further reading: https://blog.miguelgrinberg.com/post/it-s-time-for-a-change-datetime-utcnow-is-now-deprecated
    """
    return datetime.now(UTC)


def time_now() -> str:
    """
    Get the current time.

    Retrieve the current time in the format specified in consts.

    Returns:
        str: The current time
    """
    return utc_now().strftime(consts.LOG_TIME_FMT)


def are_we_superuser() -> bool:
    """
    Checks if PEAT is running with root privileges (effective user ID/euid
    of 0) or Administrator on Windows.
    """
    if state.superuser_privs is not None:
        return bool(state.superuser_privs)

    try:
        state.superuser_privs = os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes

            state.superuser_privs = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            log.exception("Failed to check Windows admin status")
    except Exception:
        log.exception("Failed to check superuser status")

    return bool(state.superuser_privs)


def rgetattr(obj, attr: str, *args) -> Any:
    """
    Recursive version of the builtin :func:`getattr`.
    """

    # Source: https://stackoverflow.com/a/31174427
    def _getattr(obj, attr):
        return getattr(obj, attr, *args)

    return functools.reduce(_getattr, [obj, *attr.split(".")])


def rsetattr(obj, attr: str, val) -> Any:
    """
    Recursive version of the builtin :func:`setattr`.
    """

    # Source: https://stackoverflow.com/a/31174427
    pre, _, post = attr.rpartition(".")
    return setattr(rgetattr(obj, pre) if pre else obj, post, val)


def deep_get(dictionary: dict, keys: str, default=None) -> Any:
    """
    Safely read the value of a deeply nested key from
    nested :class:`dict` objects.

    .. code-block:: python

       >>> from peat.utils import deep_get
       >>> x = {'1': {'2': {'3': 'hi'}}}
       >>> deep_get(x, "1.2.3")
       'hi'

    Args:
        dictionary: Dictionary to search
        keys: dot-separated string of keys to query, e.g. ``"1.2.3"`` to query
            a dict like ``{'1': {'2': {'3': 'hi'}}}``
        default: Default value to return if the query fails, similar to
            :meth:`dict.get`

    Returns:
        The value of the object, or the value of ``default`` if the query
        failed (this is :obj:`None` if unset).
    """

    # Source: https://stackoverflow.com/a/46890853
    return functools.reduce(
        lambda d, key: d.get(key, default) if isinstance(d, dict) else default,
        keys.split("."),
        dictionary,
    )


def is_ip(to_check: str) -> bool:
    """
    Check if a string is a IPv4 or IPv6 address.
    """
    if not to_check:
        return False
    try:
        ip_address(to_check.strip())
        return True
    except ValueError:
        return False


def is_email(to_check: str) -> bool:
    """
    Check if a string is a email address.
    """
    return bool(
        to_check
        and re.fullmatch(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", to_check.strip()
        )
    )


def is_mac(to_check: str) -> bool:
    """
    Check if a string is a MAC address.
    """
    return bool(
        to_check
        and len(to_check) == 17
        and ":" in to_check
        and re.fullmatch(MAC_RE_COLON, to_check, re.ASCII)
    )
