"""
Interact with Woodward MicroNet Plus control systems.

Listening network services

- FTP (TCP 21)

Authors

- Christopher Goes
- Patrica Schulz
- Jessica Robinson
"""

import ftplib
import pathlib
from pathlib import Path

from dateutil import parser

from peat import CommError, DeviceData, DeviceModule, IPMethod
from peat.protocols import FTP

from . import parse_micronet


class MicroNet(DeviceModule):
    """Woodward MicroNet Plus."""

    device_type = "Control System"
    vendor_id = "Woodward"
    vendor_name = vendor_id
    brand = "MicroNet"
    model = "Plus"

    default_options = {"ftp": {"timeout": 10, "user": "ServiceUser", "pass": "ServiceUser"}}

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Verify that this device is a Micronet.
        The text in the pulled file Registry.txt
        should contain the string "Micronet".
        """
        verified = False
        port = int(dev.options["ftp"]["port"])
        timeout = float(dev.options["ftp"]["timeout"])

        try:
            with FTP(dev.ip, port, timeout=timeout) as f:
                cls.log.info("Attempting to verify")
                f.login(user=dev.options["ftp"]["user"], passwd=dev.options["ftp"]["pass"])

                # attempt to pull boot file via FTP
                f.cwd("HD1Flash/Registry")
                filename = "Registry.txt"
                boot_text = f.download_binary(filename)

                # check if "micronet" is in the pulled boot file to confirm device
                if boot_text:
                    boot_text_decoded = boot_text.decode()
                    if "micronet" in boot_text_decoded.lower():
                        verified = True
                        cls.log.info("Device verified as Micronet")
                    else:
                        cls.log.warning("Unable to verify device via FTP")
        except (OSError, CommError) as err:
            cls.log.error(f"Failed to connect to {dev.ip}: {err}")
            raise err from None

        return verified

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """
        If there is a file specified in command line args, pull that file
        only. Otherwise, pull all files
        """
        # TODO: configurable timeout
        with FTP(dev.ip, dev.options["ftp"]["port"], timeout=100) as ftp:
            ftp.login(dev.options["ftp"]["user"], dev.options["ftp"]["pass"])
            # find the top-level directory
            last_dir = ""
            try:
                # for some reason, f.pwd() isn't working, so we have to use this
                # approach instead
                while last_dir != ftp.cmd("PWD").split('"')[1]:
                    try:
                        last_dir = ftp.cmd("PWD").split('"')[1]
                        ftp.cwd("..")
                    except ftplib.all_errors as e:
                        if "No such file or directory" not in str(e):
                            cls.log.exception("Failed FTP pull")
            except ftplib.all_errors:
                cls.log.exception("Failed FTP pull")
                return False

            # get all the files and folders down the tree
            cls.pull_all_files(dev, last_dir, dev._out_dir, ftp)
            cls.get_gap_info(dev)
            return True

    @classmethod
    def is_file(cls, filename: str, ftp: FTP) -> bool:
        """Check if a given file is a file or directory"""
        try:
            lst = ftp.nlst(filename)
            if lst and ftp.file_size(filename):
                if "total" in lst[0] and lst[1] == filename:
                    return True
                elif lst[0] == filename:
                    return True
                else:
                    return False
            else:
                return False
        except ftplib.all_errors:
            return False

    @classmethod
    def pull_all_files(cls, dev: DeviceData, directory: str, output_dir: pathlib.Path, ftp: FTP):
        """
        Pull all files available recursively

        Args:
            directory: the next directory to investigate (current directory when
                this function is called)
            output_dir: the last path (path to direcrtory),
                which will be added on to each function call
        """
        # skip these special directories
        if directory and directory not in {".", ".."}:
            path = ""
            curr_dir = ftp.cmd("PWD").split('"')[1]
            # We want to mirror the directory structure of the target
            # first check if this is the top level dir,
            # this if just avoids having two path objects with separate anchors
            if directory != "/":
                path = output_dir / directory
            else:
                path = output_dir

            # Now pull all the files and make a list of all the folders
            dir_res = ftp.dir()
            if not dir_res:
                cls.log.error("ftp dir failed")
                return

            folder_list = []
            file_list = dir_res[0]

            # if there are files in the directory, iterate through them
            if file_list:
                for filename in file_list:
                    if cls.is_file(filename, ftp):  # if file, download and save locally
                        try:
                            ftp.download_binary(filename, dev.get_out_dir() / path / filename)
                            # get file hashes and store in dev.extra
                            timestamp = ftp.cmd(f"MDTM {filename}").split()[1]
                            date_time = parser.parse(timestamp)
                            parse_micronet.create_artifact(
                                dev,
                                dev.get_out_dir() / path / filename,
                                date_time.isoformat(),
                            )
                        except ftplib.all_errors:
                            cls.log.error(f"Unable to retrieve {filename}")
                            raise ftplib.all_errors from None
                    else:  # this is a directory, store in list of folders
                        try:
                            ftp.cwd(filename)
                            folder_list.append(filename)
                            ftp.cwd(curr_dir)
                        except ftplib.all_errors as err:
                            cls.log.error(f"Failed pull: {err}")

                    # look for files we want to parse
                    if "vxWorks" in filename:
                        cls.log.info("Attempting to extract info from firmware")
                        # get last modified timestamp from ftp server
                        timestamp = ftp.cmd(f"MDTM {filename}").split()[1]
                        date_time = parser.parse(timestamp)
                        cls.log.info(f"Firmware last modified at {date_time}")

                        filepath = Path(dev.get_out_dir(), path, filename)

                        parse_micronet.get_info_firmware(dev, filepath, date_time)

                    if "bootrom" in filename.lower():
                        cls.log.info("Attempting to extract info from boot firmware")
                        # get last modified timestamp from ftp server
                        timestamp = ftp.cmd(f"MDTM {filename}").split()[1]
                        date_time = parser.parse(timestamp)
                        cls.log.info(f"Boot firmware last modified at {date_time}")

                        filepath = Path(dev.get_out_dir(), path, filename)

                        parse_micronet.get_info_bootrom(dev, filepath, date_time)

                    if "Log.txt" in filename[0:7] and "HD1Flash" in str(path):
                        cls.log.info(f"Attempting to extract info from {filename}")
                        parse_micronet.parse_log(dev, dev.get_out_dir() / path / filename)

                # Now recurse over the folders
                for folder in folder_list:
                    ftp.cwd(folder)
                    cls.pull_all_files(dev, folder, path, ftp)
                    ftp.cwd(curr_dir)

        cls.update_dev(dev)

    @classmethod
    def get_gap_info(cls, dev: DeviceData) -> None:
        """
        Determine most recent GAP file used from dev.event,
        Get file info on that GAP file, store in Logic
        """
        for event in reversed(dev.event):
            if "Loading" in event.message and "gap" in event.message:
                filename = event.message.split(" ")[1]
                break  # only get most recent event for gap file load

        # get GAP file info from log file (or just dev.event?)
        for artifact in dev.extra.get("file_artifacts"):
            if artifact["filename"] == filename:
                parse_micronet.get_gap_info(
                    dev, filename, artifact["filepath"], artifact["timestamp"]
                )
                break


MicroNet.ip_methods = [
    IPMethod(
        name="Micronet FTP login",
        description=str(MicroNet._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=MicroNet._verify_ftp,
        reliability=8,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    )
]

__all__ = ["MicroNet"]
