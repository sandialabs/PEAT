import timeit
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from peat import DeviceData, DeviceError, config, log, utils
from peat.protocols import FTP

from .sel_serial import SELSerial
from .sel_telnet import SELTelnet


def clean_filenames(filenames: list[bytes | str]) -> list[str]:
    """
    Some file listings contain embedded null bytes.
    """
    clean = []

    for filename in filenames:
        if isinstance(filename, bytes):
            filename = filename.decode()
        clean.append(filename.strip().replace("\x00", ""))

    return clean


def _method_name(comms: FTP | SELTelnet | SELSerial) -> str:
    if isinstance(comms, FTP):
        return "FTP"
    elif isinstance(comms, SELTelnet):
        return "Telnet"
    elif isinstance(comms, SELSerial):
        return "Serial"
    else:
        raise DeviceError(f"Invalid comms class: {comms.__class__.__name__}")


def download_files(
    files: list[str],
    comms: FTP | SELTelnet | SELSerial,
    save_dir: Path | None,
    handle_download_errors: bool = True,
) -> dict[str, dict[str, bytes | str | Path]]:
    """
    Download a selected list of files from a relay in a comms-agnostic manner.

    .. code-block:: python

       {
           "filename": {
               "name": filename,
               "data": file_data,
               "raw_path": path,
               "device_path": PurePosixPath(...),
               "local_path": Path(...),
           },
           ...
       }
    """

    method = _method_name(comms)

    log.info(f"Retrieving {len(files)} files from {comms.address} via {method}")

    if isinstance(comms, SELTelnet) and not comms.can_download_files():
        raise DeviceError(
            f"{comms.address} is not capable of downloading files "
            f"via Telnet. Terminating Telnet download."
        )

    # filename: {path, data}
    all_file_data = {}

    for path in files:
        # path can be:
        # - "SET_P1.TXT"
        # - "SETTINGS SET_P1.TXT"
        # - "SETTINGS/SET_P1.TXT" (need to confirm)
        fmt_path = path.split(" ")[-1].replace("\\", "/")
        if fmt_path[0] != "/":
            fmt_path = f"/{fmt_path}"
        path_obj = PurePosixPath(fmt_path)
        filename = path_obj.name

        log.info(f"Retrieving '{path}' from {comms.address} via {method}")

        try:
            file_data = comms.download_binary(path, save_to_file=False)

            if file_data is None:
                log.error(
                    f"Failed to download {filename} "
                    f"from {comms.address} via {method}"
                )
                continue

            if isinstance(file_data, bytes) and path.upper().endswith(".TXT"):
                file_data = file_data.decode("utf-8")

            file_dict = {
                "name": filename,
                "data": file_data,  # bytes or str
                "raw_path": path,
                "device_path": path_obj,
                "local_path": "",
            }

            if save_dir:
                local_path = save_dir / filename
                if isinstance(file_data, str) and file_data.strip() == "=>":
                    log.warning(
                        f"File '{filename}' only has '=>' as contents, "
                        f"probably as a artifact of a Telnet mis-parse. "
                        f"Writing empty data instead."
                    )
                    utils.write_file("", local_path)
                else:
                    utils.write_file(file_data, local_path)
                file_dict["local_path"] = local_path

            # Check for duplicates. An example of this is on the 700G,
            # which has EVENTS/HISTORY.TXT and REPORTS/HISTORY.TXT,
            # which contain the same data (timestamp will differ tho),
            # but have different parent directories.
            if filename in all_file_data:
                ext_count = 1
                while f"{filename}.{ext_count}" in all_file_data:
                    ext_count += 1

                updated_filename = f"{filename}.{ext_count}"
                log.warning(
                    f"{filename} already exists in all_file_data! "
                    f"Saving to {updated_filename} instead."
                )
                filename = updated_filename

            all_file_data[filename] = file_dict

        except Exception as ex:
            if handle_download_errors:
                log.error(
                    f"Failed to retrieve '{path}' from "
                    f"{comms.address} via {method}: {ex}"
                )
            else:
                raise ex from None

    log.info(f"Retrieved {len(files)} files from {comms.address} via {method}")

    return all_file_data


def filter_names(
    paths: list[str],
    only: list[str] | None = None,
    never: list[str] | None = None,
) -> list[str]:
    if not only and not never:  # short-circuit common case
        return sorted(paths)

    if only is not None and not isinstance(only, list):
        raise DeviceError(
            f"'only' filters must be a list, not '{type(only).__name__}' "
            f"(value provided: {repr(only)})"
        )

    if never is not None and not isinstance(never, list):
        raise DeviceError(
            f"'never' filters must be a list, not '{type(never).__name__}'"
            f"(value provided: {repr(never)})"
        )

    filtered = set()

    for path in sorted(paths):
        if only:
            for allow_pattern in only:
                if path == allow_pattern or fnmatch(
                    path.lower(), allow_pattern.lower()
                ):
                    filtered.add(path)
                    break
        elif never:
            excluded = False
            for exclude_pattern in never:
                if path == exclude_pattern or fnmatch(
                    path.lower(), exclude_pattern.lower()
                ):
                    excluded = True
                    break
            if not excluded:
                filtered.add(path)

    return sorted(filtered)


def pull_files(
    dev: DeviceData, comms: FTP | SELTelnet | SELSerial
) -> dict[str, dict[str, bytes | str]]:
    """
    Recursively download all files from a relay in a comms-agnostic manner.

    Args:
        dev: The device to pull from
        comms: Communication method to use, as a class instance. It must have
            the methods ``list_files()`` and ``download_binary``.

    Returns:
        The files downloaded, keyed by filename, with value being a dict including
        the file data, the device path, and the local path (if it was saved locally).
    """
    method = _method_name(comms)
    start_time = timeit.default_timer()

    log.info(f"Pulling relay config files from {dev.address} via {method}")

    # Directory to save raw files to
    # Format: peat_results/<run-dir>/devices/{address}/relay_files_{timestamp}/*
    configs_dir = None
    if config.DEVICE_DIR:
        configs_dir = dev.get_sub_dir("relay_files")

    # Determine files to download from root directory and any sub-directories
    populate_file_listing(dev, comms)

    log.trace(f"{method} file listing: {dev.extra['file_listing']}")

    to_download = filter_names(
        list(dev.extra["file_listing"].keys()),
        only=dev.options["sel"]["only_download_dirs"],
        never=dev.options["sel"]["never_download_dirs"],
    )

    log.info(f"Directories to download from {dev.address} via {method}: {to_download}")

    # Raw and file paths contents of all files downloaded
    all_files = {}

    # Download files from each directory
    for dirname in to_download:
        # Filter files to download based on config settings
        filenames = filter_names(
            dev.extra["file_listing"][dirname],
            dev.options["sel"]["only_download_files"],
            dev.options["sel"]["never_download_files"],
        )

        if not filenames:
            log.warning(
                f"Skipping directory {dirname} on {dev.address}, "
                f"it's either empty or there are no files that "
                f"weren't filtered by the 'only_download_files' or "
                f"'never_download_files' options"
            )
            continue

        # Determine file path to use for download
        if dirname != "/" and not (
            dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]
        ):
            # Telnet requires space between directory and file name
            # Technically you can get away with a slash, but some devices don't like this.
            sep = "/" if isinstance(comms, FTP) else " "
            paths = [f"{dirname}{sep}{file}" for file in filenames]
        else:
            paths = filenames

        # Save files to a sub-directory matching the structure on the device,
        # if file saving is enabled (if configs_dir != None).
        sub_dir = configs_dir
        if configs_dir and dirname != "/":
            sub_dir = configs_dir / dirname

        try:
            # Change directory if needed for older devices
            if (
                dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]
            ) and isinstance(comms, FTP):
                comms.cd(dirname)  # cd <dirname> => retr <file> => cd ..

            downloaded = download_files(
                files=paths,
                comms=comms,
                save_dir=sub_dir,
                handle_download_errors=dev.options["sel"].get(
                    "handle_download_errors", True
                ),
            )

            all_files.update(downloaded)

            # Restore directory location
            if (
                dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]
            ) and isinstance(comms, FTP):
                comms.cd("..")
        except Exception as ex:
            log.warning(
                f"Failed to retrieve files from {dirname} "
                f"on {dev.address} via {method}: {ex}"
            )

    duration = timeit.default_timer() - start_time
    log.info(
        f"Pulled {len(all_files)} files from {dev.address} via {method} "
        f"(duration: {utils.fmt_duration(duration)})"
    )
    log.debug(
        f"Files pulled from {dev.address} via {method}: "
        f"{', '.join(all_files.keys())}"
    )

    # TODO: if "SET_ALL.TXT" not in files and SET_x.TXT in files,
    #  then reconstruct SET_ALL from individual settings files
    dev._cache["all_files"] = all_files

    # Add files to related.files, in case they aren't already
    for file_dict in all_files.values():
        dev.related.files.add(file_dict["name"])

    return all_files


def populate_file_listing(
    dev: DeviceData, comms: FTP | SELTelnet | SELSerial
) -> None:
    # ["DIAGNOSTICS", "EVENTS", "HMI", "REPORTS", "SER", "STATUS", "SETTINGS"]
    if not dev.extra.get("file_listing"):
        if isinstance(comms, FTP):
            slash_listing = comms.nlst_files()
        else:
            slash_listing = comms.list_files()
        dev.extra["file_listing"] = {"/": clean_filenames(slash_listing)}

    if not dev.extra.get("settings_root_directory"):
        if "SETTINGS" in dev.extra["file_listing"]["/"]:
            dev.extra["settings_root_directory"] = "SETTINGS"
        else:
            dev.extra["settings_root_directory"] = "/"
        log.debug(
            f"Settings root directory for {dev.address}: "
            f"'{dev.extra['settings_root_directory']}'"
        )

    root_files = []
    files_on_dev = set()
    dirs_on_dev = set()

    for file in dev.extra["file_listing"]["/"]:
        # Process sub-directories
        # Note(cegoes): Files will always have "." as far as I know
        if "." not in file and file not in dev.extra["file_listing"]:
            if isinstance(comms, FTP):
                listing = clean_filenames(comms.nlst_files(file))
            else:
                listing = clean_filenames(comms.list_files(file))

            # Handle 351 and older devices that act in a weird way...
            # 'ls <directory>' doesn't work, you have to cd to the directory,
            # then run 'ls' to get a proper file listing.
            # cd <dirname> => ls => cd ..
            if file in listing and isinstance(comms, FTP):
                comms.cd(file)
                listing = clean_filenames(comms.nlst_files())
                comms.cd("..")
                dev.extra["sel_old_ftp"] = True

            log.trace(f"Files in '{file}' from {dev.address}: {listing}")
            files_on_dev.update(listing)
            dirs_on_dev.add(file)

            # Sets the sub-directory to be a separate part of the file listing
            # dict from the files in the root directory, e.g.
            #   dev.extra["file_listing"]["/"] = ["CFG.XML", ...]
            #   dev.extra["file_listing"]["SETTINGS"] = ["SET_1.TXT", ...]
            dev.extra["file_listing"][file] = listing
        else:
            root_files.append(file)
            files_on_dev.add(file)

    dirs_on_dev.add("/")

    dev.extra["file_listing"]["/"] = root_files
    dev.extra["num_directories_on_device"] = len(dirs_on_dev)
    dev.extra["num_files_on_device"] = len(files_on_dev)
    dev.extra["all_dirs_on_device"] = sorted(dirs_on_dev)
    dev.extra["all_files_on_device"] = sorted(files_on_dev)

    dev.related.files.update(files_on_dev)
