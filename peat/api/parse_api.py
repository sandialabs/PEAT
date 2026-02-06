import sys
import timeit
from fnmatch import fnmatchcase
from operator import itemgetter
from pathlib import Path
from typing import TextIO

from peat import (
    DeviceData,
    DeviceModule,
    __version__,
    config,
    consts,
    datastore,
    log,
    module_api,
    state,
    utils,
)


def parse(
    filepaths: str | Path | list[str | Path],
    device_types: list[type[DeviceModule] | str] | None = None,
    sub_dirs: bool = True,
) -> dict[str, dict | list | str | float | int] | None:
    """
    Find and parse device and/or project files.

    Args:
        filepaths: File or directory paths to parse,
            or ``"-"`` to read from standard input (``stdin``).
        device_types: names, aliases, or classes of PEAT device modules to use.
            If :class:`None`, all currently imported modules are used.
        sub_dirs: If sub-directories of a directory path should be searched

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    if isinstance(filepaths, (str, Path)):
        filepaths = [filepaths]

    log.info(f"Parsing {len(filepaths)} filepaths")

    paths = []
    for fp in filepaths:
        checked = utils.check_file(fp)
        if not checked:
            return None
        paths.append(checked)

    # Convert mixed device types/aliases into canonical PEAT device modules
    mods = module_api.lookup_types(device_types)
    if not mods:
        log.error("No valid device types specified for parse")
        return None

    log.debug(
        f"Filtering parse-capable modules out of {len(mods)} "
        f"modules ({[x.__name__ for x in mods]})"
    )
    resolved_types = []
    for mod in mods:
        if mod.filename_patterns:
            resolved_types.append(mod)
        # elif to prevent module being added twice
        elif mod.can_parse_dir:
            for fp in paths:
                if str(fp) != "-" and Path(fp).is_dir():
                    resolved_types.append(mod)
                    break

    if not resolved_types:
        log.error(
            f"None of the specified modules support parsing (modules: "
            f"{str([x.__name__ for x in mods]).strip('[]')})"
        )
        return None
    log.debug(
        f"Parsing using {len(resolved_types)} parse-capable modules: "
        f"{str([x.__name__ for x in resolved_types]).strip('[]')}"
    )

    # Disable automatic lookup of host information unless user has explicitly enabled it
    for key in ["RESOLVE_IP", "RESOLVE_MAC", "RESOLVE_HOSTNAME"]:
        if not config.non_default(key):
            log.trace(f"Setting default config '{key}' to False for parsing")
            setattr(config, key, False)

    # Should only specify a single device type for reading from stdin
    if len(resolved_types) > 1 and any(str(fp) == "-" for fp in paths):
        log.error(
            "You must specify a single device type for input from standard "
            "input (stdin). Add the '-d' flag, e.g. 'cat somefile | peat "
            "parse -d somemodule -'"
        )
        return None

    start_time = timeit.default_timer()
    parse_results = []
    parsed_devices = []

    # Iterate over the user-provided path arguments
    # TODO: breakup this logic a bit
    for path in paths:
        log.trace2(f"Parsing path: {path}")

        # Cases:
        # - single module + stdin (ex: 'cat set_all.txt | peat parse -d selrelay -')
        # - single module + single file (ex: 'peat parse -d selrelay ./set_all.txt')
        # - single module + directory input (ex: 'peat parse -d sage ./sage_files/')
        #
        # If a file AND single device module, don't try to use the file glob.
        #   Handles edge cases and custom names.
        # '-' -> read from standard input stream (file redirection or pipes)
        # NOTE: directories require a single module type (for now)
        if len(resolved_types) == 1 and (
            str(path) == "-"
            or Path(path).is_file()
            or (Path(path).is_dir() and resolved_types[0].can_parse_dir)
        ):
            dev = parse_data(path, resolved_types[0])

            parsed_devices.append(dev)
            parse_results.append(
                {
                    "name": path.name if isinstance(path, Path) else "stdin",
                    "path": path.as_posix() if isinstance(path, Path) else "stdin",
                    "module": resolved_types[0].__name__,
                    "results": dev.elastic() if dev else {},
                }
            )

        # Cases:
        # - single module + directory + module isn't directory-aware
        # - multi-module + single file (ex: 'peat parse ./somefile.txt')
        # - multi-module + directory (ex: 'peat parse ./somedir/')
        else:
            # Procedure:
            # - Collect tree of files
            # - Run fingerprinters on all files
            # - For remaining files, match using filename patterns.
            #      -> make this behavior configurable, like a --only-fingerprints option

            # TODO: fingerprint to detect if directory of files matches, then parse the whole
            #   directory as one device.

            all_files = sorted(utils.collect_files(Path(path), sub_dirs))

            for dev_cls in resolved_types:
                # TODO: during a pass of multiple files, group files by module
                # pass the same dev object to multiple parses? or update devices'
                # parse logic to do smarter lookups?
                # TODO: Add something to API to specify a group of files
                #   should be passed? (from ion.py TODOs)
                for file_path in find_parsable_files(all_files, dev_cls):
                    dev = parse_data(file_path, dev_cls)

                    parsed_devices.append(dev)
                    parse_results.append(
                        {
                            "name": file_path.name,
                            "path": file_path.as_posix(),
                            "module": dev_cls.__name__,
                            "results": dev.elastic() if dev else {},
                        }
                    )

    # * Deduplicate *
    datastore.deduplicate(prune_inactive=False)

    # * Push results to Elasticsearch *
    if state.elastic:
        for d_dev in datastore.objects:
            if d_dev not in parsed_devices:  # skip any not part of this parse
                log.trace(f"Skipping device not part of parse: {d_dev.get_id()}")
                continue
            d_dev.export_to_elastic()

    # * Construct the parse results summary *
    parse_results.sort(key=itemgetter("module"))  # sort by device module

    parse_successes = []
    parse_failures = []
    for result in parse_results:
        if result["results"]:
            parse_successes.append(result)
        else:
            del result["results"]
            parse_failures.append(result)

    parse_duration = timeit.default_timer() - start_time

    parse_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "parse_duration": parse_duration,
        "parse_modules": module_api.lookup_names(device_types),
        "input_paths": filepaths,
        "files_parsed": [r["path"] for r in parse_results],
        "num_files_parsed": len(parse_results),
        "num_parse_successes": len(parse_successes),
        "num_parse_failures": len(parse_failures),
        "parse_failures": parse_failures,
        "parse_results": parse_successes,
    }

    # * Save parse results summary to a file *
    utils.save_results_summary(parse_summary, "parse-summary")

    # * Push parse results summary to Elasticsearch *
    if state.elastic:
        log.info(
            f"Pushing parse result summary to {state.elastic.type} "
            f"(index basename: {config.ELASTIC_PARSE_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_PARSE_INDEX, parse_summary):
            log.error(f"Failed to push parse result summary to {state.elastic.type}")

    log.info(
        f"Completed parsing of {len(parse_results)} files in {utils.fmt_duration(parse_duration)}"
    )
    return parse_summary


def parse_data(source: str | Path | TextIO, dev_cls: type[DeviceModule]) -> DeviceData | None:
    log.info(f"Parsing {dev_cls.__name__} file '{source}'")

    # Read data as bytes from stdin (CLI input, e.g. pipes or redirection)
    if isinstance(source, str) and source == "-":
        log.debug("Parse data is from standard input (stdin)")
        source = sys.stdin
    # source is assumed to be a filename, make it a Path for DeviceModule.parse()
    elif isinstance(source, str):
        source = Path(source)

    try:
        parsed_dev = dev_cls.parse(source)
    except Exception as ex:
        log.exception(f"Failed to parse '{source}' due to exception: {ex}")
        state.error = True
        return None

    if not parsed_dev:
        log.warning(f"Failed to parse data from '{source}' using {dev_cls.__name__}")
        state.error = True
        return None

    return parsed_dev


def find_parsable_files(files: list[str], dev_cls: type[DeviceModule]) -> list[Path]:
    """Find files that are parsable by a device type."""
    parsable_files = set()  # Prevent conflicts
    log.debug(f"Searching {len(files)} files for {dev_cls.__name__} files")

    # Should the fingerprinting happen separately from filename matching?
    # Should it happen after it? Or in parallel?

    # TODO: can this step be threaded?

    for pattern in dev_cls.filename_patterns:
        if pattern[0] != "*":
            pattern = f"*{pattern}"

        log.trace3(f"Checking pattern '{pattern}' for {dev_cls.__name__}")
        for filename in files:
            if fnmatchcase(filename.lower(), pattern.lower()):
                parsable_files.add(filename)

    if not parsable_files:
        log.debug(f"No parsable files found for {dev_cls.__name__}")
        return []

    sorted_files = sorted(parsable_files)  # convert set to list and sort
    log.trace2(f"Parsable files for {dev_cls.__name__}: {sorted_files}")
    sorted_paths = [Path(file).resolve() for file in sorted_files]
    return sorted_paths


__all__ = ["parse"]
