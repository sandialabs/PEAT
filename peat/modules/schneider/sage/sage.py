"""
Schneider Electric Sage RTUs.

AMD x86 CPU.
Default creds are ``Admin``/``Telvent1!`` for most authenticated services.

TCP/UDP Open Ports

- FTP (TCP 21)
- SSH (TCP 22)
- Telnet (TCP 23)
- HTTP (TCP 80)
- HTTPS (TCP 443)
- L2TP (UDP 1701)

Authors

- Aaron Lombrozo
- Aidan Kollar
- Christopher Goes
- James Gallagher
- Ryan Vrecenar
"""

import functools
import os
import tarfile
from datetime import datetime
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal

from peat import (
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    ParseError,
    config,
    datastore,
    exit_handler,
    utils,
)
from peat.data.data_utils import merge_models
from peat.data.models import Memory
from peat.parsing.command_parsers import ArpParser, IfconfigParser
from peat.protocols import FTP, HTTP

from . import sage_parse
from .sage_commands import (
    convert_memory_reads_to_hex_strings,
    find_duplicate_memory_reads,
    mark_duplicate_tasks,
    parse_ipf,
    parse_sysvar_list,
    parse_user_list,
    parse_vxworks_version,
    process_sysvar_list,
    process_user_list,
    process_vxworks_version,
    save_memory_reads_to_disk,
)
from .sage_http import SageHTTP
from .sage_ssh import SageSSH
from .sage_telnet import SageTelnet

# TODO: get model (3030, 3030M, 2400) from configs and/or 'version' telnet command


class Sage(DeviceModule):
    """
    Schneider Electric Sage RTU.
    """

    device_type = "RTU"
    vendor_id = "Schneider"
    vendor_name = "Schneider Electric"
    brand = "Sage"
    model = ""
    filename_patterns = [
        "*_Config*.tar.gz",
        "*_config*.tar.gz",
        "*_Firmware*.tar.gz",
        "*_firmware*.tar.gz",
        "rtusetup.xml",
        "ACCESS.XML",
    ]
    can_parse_dir = True
    annotate_fields = {
        # AMD x86 CPU, according to Aaron
        "architecture": "x86",
        # TODO: what is the endian-ness of the sage? big or little?
        # "endian": "",
        "os.name": "VxWorks",
        "os.vendor.name": "Wind River Systems",
        "os.vendor.id": "WindRiver",
    }
    default_options = {
        "sage": {
            "pull_methods": ["telnet", "ftp", "ssl", "ssh", "sftp", "http", "https"],
            "ftp_filesystems": [
                "/ata0a",
                "/ramDrv",
            ],
            "ssh_filepaths": [
                "/ata0a/scripts/vxworks_start.scp",
                "/ata0a/scripts/startup.scp",
            ],
        },
        "ftp": {
            "user": "Admin",
            "pass": "Telvent1!",
        },
        "telnet": {
            "user": "Admin",
            "pass": "Telvent1!",
            "timeout": 10.0,
        },
        "ssh": {
            "user": "Admin",
            "pass": "Telvent1!",
            "passphrase": "Telvent1!",
            "timeout": 10.0,
            "key_filename": "",
            "look_for_keys": False,
            "disabled_algorithms": {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]},
        },
        "web": {
            "user": "Admin",
            "pass": "Telvent1!",
            "timeout": 30.0,
        },
    }

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Verify via FTP login and check of current directory ('pwd').
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via FTP (timeout: {timeout})")

        # TODO: preserve FTP session between verify and pull
        try:
            with FTP(dev.ip, port, timeout) as ftp:
                welcome_string = ftp.ftp.getwelcome()
                ftp.process_vxworks_ftp_welcome(welcome_string, dev)

                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]
                if not ftp.login(username, password):
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: login failed (username: {username})"
                    )
                    return False
                dev.related.user.add(username)

                pwd = ftp.pwd()
                if not pwd:
                    cls.log.debug(f"Failed to verify {dev.ip} via FTP: 'pwd' failed")
                    return False
                dev.extra["ftp_pwd"] = pwd

                # TODO: check if file(s) are present to verify it's a Sage INSTEAD of pwd
                # -> use ftp.find_file()

                if "/ata0a" not in pwd.lower():
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: current directory is not /ata0a/"
                    )
                    return False

                dev._cache["sage_ftp_fingerprinted"] = True
        except Exception as ex:
            cls.log.debug(f"Failed to verify {dev.ip} via FTP: {ex}")
            return False
        cls.log.debug(f"Verified {dev.ip}:{port} via FTP")
        return True

    @classmethod
    def _verify_protocol(
        cls, dev: DeviceData, protocol: Literal["ssh", "telnet"] = "telnet"
    ) -> bool:
        """
        Verify if the given protocol can connect to Sage (ssh/telnet for now).

        Args:
            dev (DeviceData): Device specific data and configuration.
            protocol (str): Which protocol to use (telnet/ssh).

        Returns:
            bool: Check if a device is a Sage RTU by logging in.
        """
        timeout = dev.options[protocol]["timeout"]
        port = dev.options[protocol]["port"]

        # NOTE: a "with" statement isn't used here to allow PEAT to preserve the
        # session if successfully verified for use in _pull_protocol().
        if protocol == "telnet":
            conn = SageTelnet(dev.ip, port, timeout, dev=dev)
        elif protocol == "ssh":
            conn = SageSSH(dev.ip, port, timeout, dev=dev)
        else:
            raise ValueError("Protocol {protocol} not supported!")

        try:
            username = dev.options[protocol]["user"]
            password = dev.options[protocol]["pass"]
            logged_in = conn.login(username, password)

            if not logged_in:
                cls.log.debug(f"Failed {protocol.capitalize()} verify for {dev.ip}: login failed")
                conn.disconnect()
                return False
            dev.related.user.add(username)

            if protocol != "ssh":
                if not any("VxWorks" in x for x in conn.all_output):
                    cls.log.debug(
                        f"Failed {protocol.capitalize()} verify for {dev.ip}: "
                        f"no 'VxWorks' string in login prompt"
                    )
                    conn.disconnect()
                    return False

            # TODO: run command to check if it's a sage (check for specific files)
            # TODO: run command to get OS info

            # Cache the session for use in _pull_protocol(), and ensure
            # the connection is closed properly when PEAT exits.
            dev._cache[f"sage_{protocol}_session"] = conn
            exit_handler.register(dev._cache[f"sage_{protocol}_session"].disconnect, "CONNECTION")
            dev._cache[f"sage_{protocol}_fingerprinted"] = True

            return True
        except Exception as ex:
            cls.log.trace(f"Failed {protocol.capitalize()} verify due to exception: {ex}")
            conn.disconnect()
            return False

    @classmethod
    def _verify_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Verify a device is a Sage RTU via parsing of the web interface.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.debug(f"Verifying {dev.ip}:{port} using {protocol} (timeout: {timeout})")

        with HTTP(dev.ip, port, timeout) as http:
            resp = http.get(protocol=protocol)
            if not resp or not resp.text:
                return False
            page_data = resp.text

        if "Telvent" in page_data and "Config@WEB" in page_data:
            cls.log.debug(f"{protocol.upper()} verification successful for {dev.ip}:{port}")
            return True

        return False

    @classmethod
    def _verify_https_ssl_certificate(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a Sage RTU via SSL certificate inspection.
        """
        timeout = dev.options["https"]["timeout"]
        port = dev.options["https"]["port"]

        cls.log.debug(f"Verifying {dev.ip}:{port} using SSL (timeout: {timeout})")

        with HTTP(dev.ip, port, timeout) as http:
            parsed_cert = http.get_ssl_certificate()

        if not parsed_cert:
            return False

        merge_models(dev.x509, parsed_cert)

        entity = parsed_cert.subject
        if not entity.organization:
            entity = parsed_cert.issuer
        if not entity.organization:
            cls.log.debug(f"No 'subject' or 'issuer' in SSL certificate from {dev.ip}")
            return False

        dev._cache["sage_ssl_fingerprinted"] = True

        if entity.organization == "Telvent" and entity.organizational_unit == "RTU":
            cls.log.debug(f"SSL verification successful for {dev.ip}:{port}")
            return True

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        pull_successful = False

        # ** Telnet/SSH pulling **
        for pull_type in ["telnet", "ssh"]:
            pull_type_cap = pull_type.capitalize()
            if pull_type not in dev.options["sage"]["pull_methods"]:
                cls.log.warning(
                    f"Skipping method '{pull_type_cap}' for pull from {dev.ip}: "
                    f"'{pull_type_cap}' not listed in 'sage.pull_methods' option"
                )
            elif (
                dev.service_status({"protocol": pull_type, "port": dev.options[pull_type]["port"]})
                == "closed"
            ):
                cls.log.warning(
                    f"Failed to pull {pull_type_cap} on {dev.ip}: "
                    f"{pull_type_cap} service is closed"
                )
            elif not dev._cache.get(
                f"sage_{pull_type}_fingerprinted"
            ) and not cls._verify_protocol(dev, pull_type):
                cls.log.warning(
                    f"Failed to pull {pull_type_cap} on {dev.ip}: "
                    f"{pull_type_cap} verification failed"
                )
            else:
                # !! hack to workaround status not being set to "verified" !!
                # !! if _verify* is called from _pull() !!
                svc = dev.retrieve(
                    "service",
                    {"protocol": pull_type, "port": dev.options[pull_type]["port"]},
                )
                if svc:
                    svc.status = "verified"
                    dev.store("service", svc, interface_lookup={"ip": dev.ip})

                tasks = cls._pull_protocol(dev, pull_type)
                pull_successful = bool(tasks)

                cls.update_dev(dev)

        # ** FTP pulling **
        if "ftp" not in dev.options["sage"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'ftp' for pull from {dev.ip}: "
                f"'ftp' not listed in 'sage.pull_methods' option"
            )
        elif (
            dev.service_status({"protocol": "ftp", "port": dev.options["ftp"]["port"]}) == "closed"
        ):
            cls.log.warning(f"Failed to pull FTP on {dev.ip}: FTP service is closed")
        elif not dev._cache.get("sage_ftp_fingerprinted") and not cls._verify_ftp(dev):
            cls.log.warning(f"Failed to pull FTP on {dev.ip}: FTP verification failed")
        else:
            # !! hack to workaround status not being set to "verified" !!
            # !! if _verify* is called from _pull() !!
            svc = dev.retrieve("service", {"protocol": "ftp", "port": dev.options["ftp"]["port"]})
            if svc:
                svc.status = "verified"
                dev.store("service", svc, interface_lookup={"ip": dev.ip})

            ftp_results = cls._pull_ftp(dev)
            pull_successful = bool(ftp_results)
            cls.update_dev(dev)

        # ** SSL certificate pulling **
        # pull https cert info as well if it wasn't scanned
        if "ssl" not in dev.options["sage"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'ssl' for pull from {dev.ip}: "
                f"'ssl' not listed in 'sage.pull_methods' option"
            )
        elif (
            dev.service_status({"protocol": "https", "port": dev.options["https"]["port"]})
            == "closed"
        ):
            cls.log.warning(f"Failed to pull SSL on {dev.ip}: HTTPS service is closed")
        elif not dev._cache.get(
            "sage_ssl_fingerprinted"
        ) and not cls._verify_https_ssl_certificate(dev):
            cls.log.warning(f"Failed to pull SSL on {dev.ip}: SSL verification failed")
        else:
            # !! hack to workaround status not being set to "verified" !!
            # !! if _verify* is called from _pull() !!
            svc = dev.retrieve(
                "service", {"protocol": "https", "port": dev.options["https"]["port"]}
            )
            if svc:
                svc.status = "verified"
                dev.store("service", svc, interface_lookup={"ip": dev.ip})
            pull_successful = True
            cls.update_dev(dev)

        # ** HTTP(S) pulling **
        for web_protocol in ["http", "https"]:
            if web_protocol not in dev.options["sage"]["pull_methods"]:
                continue

            if cls._pull_http(dev, web_protocol):  # type: ignore
                cls.log.info(f"Completed pulling {web_protocol.upper()}")
                pull_successful = True
            else:
                cls.log.warning(f"Something went wrong pulling {web_protocol.upper()}")

        return pull_successful

    @classmethod
    def _pull_ssh(cls, dev: DeviceData, client: SageSSH) -> bool:
        failures = 0
        to_download = [PurePosixPath(p) for p in dev.options["sage"]["ssh_filepaths"]]
        cls.log.info(f"Downloading {len(to_download)} files via SSH from {dev.ip}")

        for pth in to_download:
            try:
                f_data = client.write_read(f"cmd; cat {pth}")
                f_data = f_data.rstrip("->").split("\n", 1)[1].replace("\r\r", "\r")
                dev.write_file(f_data, f"ssh_files/{pth.name}")
            except Exception as ex:
                cls.log.error(f"Failed to download file {pth.name} via SSH from {dev.ip}: {ex}")
                failures += 1
                continue

        if failures:
            cls.log.error(
                f"Failed to download {failures} out of {len(to_download)} "
                f"files via SSH from {dev.ip}"
            )
            return False

        cls.log.info(f"Finished pulling from {dev.ip} using SSH")
        return True

    @classmethod
    def _pull_sftp(cls, dev: DeviceData, client: SageSSH) -> bool:
        sftp_dir = dev.get_sub_dir("sftp_files")

        try:
            client.open_sftp()
        except Exception as ex:
            cls.log.error(f"Couldn't open SFTP Connection: {ex}")
            return False

        try:
            for filesystem in dev.options["sage"]["ftp_filesystems"]:
                meta_files = client.sftp_recursive_file_walk(filesystem)
                cls.log.debug(f"Found the following directories {meta_files.keys()}")
                json_format = []
                for folder in meta_files:
                    for fl in meta_files[folder]:
                        file_stats = {
                            "name": fl.filename,
                            "permissions": fl.longname.split()[0],
                            "path": f"{folder}/{fl.filename}",
                            "modified": datetime.fromtimestamp(fl.st_mtime).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "parent": folder,
                            "size": fl.st_size,
                        }
                        json_format.append(file_stats)
                        # add filenames to dev.related
                        dev.related.files.add(fl.filename)

                dev.write_file(
                    data=json_format,
                    filename=f"sftp-file-listing-{filesystem.strip('/')}.json",
                )
                # TODO: return what files were downloaded
                client.sftp_download_files(local_dir=sftp_dir, files=json_format)
        except Exception as ex:
            cls.log.error(f"Failed to pull SFTP from {dev.ip}: {ex}")
            return False

        # Parse FTP files
        cls._parse(sftp_dir, dev)

        cls.log.info(f"Finished pulling from {dev.ip} using SFTP")
        return True

    @classmethod
    def _pull_ftp(cls, dev: DeviceData) -> bool:
        timeout = dev.options["ftp"]["timeout"]
        port = dev.options["ftp"]["port"]

        cls.log.info(f"Pulling from {dev.ip}:{port} using FTP (timeout: {timeout})")

        try:
            with FTP(dev.ip, port, timeout) as ftp:
                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                ftp.login(username, password)
                dev.related.user.add(username)

                ftp_dir = dev.get_sub_dir("ftp_files")

                # TODO: return list of files pulled + file listing information
                # TODO: record file metadata: permissions, size, flags, modification timestamp

                metadata = []
                for filesystem in dev.options["sage"]["ftp_filesystems"]:
                    cls.log.info(f"Pulling filesystem: {filesystem}")

                    listing = ftp.rdir(filesystem)
                    if not listing:
                        cls.log.error(
                            f"Failed to pull FTP files for {filesystem}: 'dir' commands failed"
                        )
                        continue

                    metadata.extend(listing[1])
                    dev.write_file(
                        data=listing[1],
                        filename=f"ftp-file-listing-{filesystem.strip('/')}.json",
                    )

                    to_download = []
                    empty_files = []
                    for file in listing[1]:
                        if file["size"] == 0:
                            empty_files.append(file)
                        else:
                            to_download.append(file)

                    if empty_files:
                        e_files = ", ".join(f["name"] for f in empty_files)
                        cls.log.warning(
                            f"Skipping {len(empty_files)} empty files on {dev.ip} "
                            f"(file size = 0): {e_files}"
                        )

                    # TODO: return what files were downloaded
                    ftp.download_files(local_dir=ftp_dir, files=to_download)
        except Exception as ex:
            cls.log.error(f"Failed to pull FTP from {dev.ip}:{port}: {ex}")
            return False

        # Parse FTP files
        cls._parse(ftp_dir, dev)

        # TODO: save list of files + metadata to dev.extra
        # TODO: save hashes of files
        # TODO: add data model for list of files (so we can diff files+hashes with hipparchus)

        # TODO: parse 'vxWorks' file using parse_micronet.get_info_firmware()

        # TODO: extract vxworks version by parsing vxWorks binary file using Jon's code
        #   BUG: incorrect os version when parsing Sage 2400 config
        #   says vxworks is 1.1, which is obviously incorrect
        #   rtusetup.xml is lies, dirty lies.

        for entry in metadata:
            if entry["name"] == "vxWorks":
                pass

        cls.log.info(f"Finished pulling from {dev.ip}:{port} using FTP")
        return True

    @classmethod
    def _pull_http(cls, dev: DeviceData, web_protocol: Literal["http", "https"]) -> bool:
        with SageHTTP(
            ip=dev.ip,
            port=dev.options[web_protocol]["port"],
            protocol=web_protocol,
            timeout=dev.options["web"]["timeout"],
            dev=dev,
        ) as http:
            try:
                cls.log.info(f"Pulling from {dev.ip}:{http.port} using {web_protocol.upper()}")

                http.get_session_cookie(
                    uname=dev.options["web"]["user"], pword=dev.options["web"]["pass"]
                )
                http.get_config_filename()

                config_data = http.download_config_file()
                if config_data:
                    c_path = dev.write_file(
                        data=config_data,
                        filename=http.config_file_name,
                        out_dir=dev.get_sub_dir("http_files"),
                    )

                    # call parse on downloaded config
                    cls.parse(c_path, dev)

                    return True

                cls.log.error(
                    f"No data for {web_protocol.upper()} file "
                    f"'{http.config_file_name}' from {dev.ip}"
                )
            except Exception as ex:
                http.log.error(
                    f"An error occurred while attempting to pull over {web_protocol.upper()}: {ex}"
                )
            finally:
                http.logout()

        return False

    @classmethod
    def _pull_protocol(cls, dev: DeviceData, protocol: Literal["telnet", "ssh"]) -> dict:
        """
        Pulls memory data from the SAGE RTU via Telnet/SSH.

        Args:
            dev (DeviceData): Device specific data and configuration.
            protocol (str): Which protocol to use (telnet/ssh).

        Returns:
            TID-indexed dictionary, or an empty dict if the pull failed.
        """
        proto_cap = "SSH" if protocol == "ssh" else protocol.capitalize()
        timeout = dev.options[protocol]["timeout"]  # type: float
        port = dev.options[protocol]["port"]  # type: int

        cls.log.info(f"Pulling from {dev.ip}:{port} using {proto_cap} (timeout: {timeout})")

        # Reuse an existing telnet/ssh session from _verify_protocol(),
        # or a previous pull in the same run.
        #
        # NOTE: a "with" statement isn't used here to allow PEAT to preserve the
        # session if successfully verified for use in _pull_protocol().
        conn = dev._cache.get(f"sage_{protocol}_session")
        if not conn:
            if protocol == "telnet":
                conn = SageTelnet(dev.ip, port, timeout, dev=dev)
            elif protocol == "ssh":
                conn = SageSSH(dev.ip, port, timeout, dev=dev)
            else:
                raise ValueError(f"Protocol {protocol} not supported!")

            dev._cache[f"sage_{protocol}_session"] = conn
            exit_handler.register(dev._cache[f"sage_{protocol}_session"].disconnect, "CONNECTION")

        if not conn.dev:
            conn.dev = dev

        # Log in to the SAGE if it hasn't been logged in
        if not conn.connected:
            username = dev.options[protocol]["user"]  # type: str
            password = dev.options[protocol]["pass"]  # type: str

            if not conn.login(username, password):
                cls.log.error(f"Failed to pull {protocol} from {dev.ip}: login failed")
                return {}
            dev.related.user.add(username)

        if protocol == "ssh":
            if "sftp" in dev.options["sage"]["pull_methods"]:
                cls.log.info(
                    "SSH protocol connection exists and sftp in pull_methods. Attempting SFTP"
                )
                if cls._pull_sftp(dev, conn):
                    cls.log.info("Completed pulling sftp")
                else:
                    cls.log.warning("Something went wrong pulling sftp")
            conn.read_until("->")
            if "ssh" in dev.options["sage"]["pull_methods"]:
                cls.log.info(
                    "SSH protocol connection exists and ssh in pull_methods. Attempting SSH"
                )
                if cls._pull_ssh(dev, conn):
                    cls.log.info("Completed pulling ssh")
                else:
                    cls.log.warning("Something went wrong pulling ssh")
            conn.read_until("->")

        # TODO: get and parse 'version' command if it hasn't
        # been done already in _verify_protocol

        # Get the current running tasks from the device
        tasks = conn.get_tasks()

        # Update partial ENTRY aliases
        conn.query_update_task_entry(tasks)

        # Mark tasks that share data
        mark_duplicate_tasks(tasks)

        # Get the memory for each task
        conn.query_read_memory_from_tasks(tasks)

        # Fill in dict with duplicated (shared) memory
        find_duplicate_memory_reads(tasks)

        # Convert memory reads to hex strings
        convert_memory_reads_to_hex_strings(tasks)

        # Save raw memory reads to disk
        if config.DEVICE_DIR:
            save_memory_reads_to_disk(dev, tasks)

        # Add memory reads to PEAT data model
        for task in tasks.values():
            mem = Memory(
                address=task["TID"].replace("0x", "").upper(),
                created=task["memory_read_time"],
                dataset="task_memory_reads",
                device=dev.ip,
                process=task["NAME"],
                size=int(task["SIZE"]),
                value=task["memory_hex"].upper(),
                extra={
                    "task_name": task["NAME"],
                    "task_entry": task["ENTRY"],
                    "task_id": task["TID"],
                    # current number of bytes of stack in use
                    "current_bytes_used": int(task["CUR"]),
                    # highest number of bytes of stack which have been in use
                    "highest_bytes_used": int(task["HIGH"]),
                    # the difference between the stack size and the
                    # highest number of bytes which have been in use
                    "margin_diff_size_and_highest": int(task["MARGIN"]),
                    # The shell command PEAT executed
                    "raw_query": task["d_query"],
                    "status": task.get("STATUS", ""),
                    "process": task.get("PROCESS", ""),
                    "options": task.get("OPTIONS", ""),
                },
            )

            if "PRI" in task:
                mem.extra["priority"] = int(task["PRI"])

            mem.annotate(dev)
            dev.memory.append(mem)

        # Only save the full dict when debugging, as it's quite large
        if config.DEBUG:
            dev.write_file(tasks, "raw-task-dict.json")

        # TODO: 'muxShow' => installed network protocols (maybe not terribly useful)

        # detailed status list (check for duplication below)
        # NOTE: "i" can be parsed similar to checkStack, using TID as the primary key
        # TODO: parse this output and store somewhere useful
        conn.query("i")

        # memory usage statistics (TODO: check for duplication below)
        conn.query("memShow")

        # ** Switch to "cmd" alternate interface (required for cmd_query calls) **
        conn.cmd_query("cmd")

        # OS information, IP, subnet mask, and gateway. See parse_vxworks_version()
        version_response = conn.cmd_query("version")
        try:
            version_info = parse_vxworks_version(version_response)
            dev.extra["version_info"] = version_info
            process_vxworks_version(version_info, dev)
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'version': {ex}")

        # contents of unknown value. just dump to file
        # Display all subsystem-known devices.
        # Just contains volumes and stdio_pty
        # TODO: parse into a dict and store in dev.extra
        conn.cmd_query("show devices")

        # Display a list of system drivers
        # Table of "drv,creat,remove,open,close,read,write,ioctl" of unknown use
        # TODO: do something useful with this
        conn.cmd_query("show drivers")

        # Displays information on the virtual memory context
        # Table of
        # "VIRTUAL ADDR,BLOCK LENGTH,PHYSICAL ADDR,PROT (S/U),CACHE,SPECIAL"
        # of unknown use
        # TODO: do something useful with this
        conn.cmd_query("vm context")

        # Show interpeak product versions
        # Contains
        # "@(#) IPCOM $Name: VXWORKS_ITER32_2015032510 $ - INTERPEAK_COPYRIGHT_STRING"
        # and similar
        conn.cmd_query("ipversion")

        # Contains many OS parameters of possible future use
        # System variables:
        #    HOME=/ata0a/ipcom/openssl
        #    etc.
        sysvar_list_response = conn.cmd_query("sysvar list")
        try:
            parsed_sysvar = parse_sysvar_list(sysvar_list_response)
            process_sysvar_list(parsed_sysvar, dev)
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'sysvar list'': {ex}")

        # Show IPCRYPTO version
        # Contains "OpenSSL 1.0.1k 8 Jan 2015" or similar
        ipcrypto_ver_response = conn.cmd_query("ipcrypto_ver")
        dev.extra["openssl_version"] = ipcrypto_ver_response

        # Contains "No SSH clients connected" or list of connected users if SSH enabled.
        # Contains "Cmd: 'ipssh_list' not found." if SSH disabled
        # TODO: process users into data model, need an example with a logged in user
        ipssh_list_response = conn.cmd_query("ipssh_list")
        dev.extra["ipssh_list"] = ipssh_list_response

        # Contains firewall statistics of possible use
        ipf_response = conn.cmd_query("ipf -S")
        try:
            parsed_firewall = parse_ipf(ipf_response)
            dev.extra["firewall_statistics"] = parsed_firewall
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'ipf -S': {ex}")

        # Current time on system.
        # Can be used to tell if system time is off
        date_response = conn.cmd_query("date")
        dev.extra["current_time"] = utils.parse_date(date_response)

        # Shows all user accounts added to system.
        # Could be used to identify extra user accounts
        user_list_response = conn.cmd_query("user list")
        try:
            parsed_users = parse_user_list(user_list_response)
            process_user_list(parsed_users, dev)
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'user list': {ex}")

        # Shows all network interfaces.
        ifconfig_response = conn.cmd_query("ifconfig -a")
        try:
            IfconfigParser.parse_and_process(ifconfig_response, dev)
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'ifconfig -a': {ex}")

        # Shows all active network connections
        # TODO: add Services to data model
        #   - resolve TID to the task name, add proper fields to data model
        # TODO: add a "process" model, store a list of processes?
        # TODO: resolve task ID to the process name and add to the Service object
        # TODO: netstat -s: networking statistics, broken down by Ip, Icmp, Tcp, Udp, Sctp
        netstat_response = conn.cmd_query("netstat")
        dev.extra["netstat_output"] = netstat_response

        # TODO:
        # netstat -r: routing table
        # explanation of routes is in the help output for netstat ("netstat -?").
        # This output is the same as the "route" command.

        # ARP table, shows all known network devices.
        arp_response = conn.cmd_query("arp -a")
        try:
            ArpParser.parse_and_process(arp_response, dev)
        except Exception as ex:
            cls.log.warning(f"Failed to parse 'arp -a': {ex}")

        cls.log.info(f"Finished pulling from {dev.ip}:{port} using {proto_cap}")

        cls.update_dev(dev)

        # return TID-indexed data
        return tasks

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        device_info = {}

        is_tar_file = False
        if file.is_file() and any(e in file.name.lower() for e in [".tar.gz", ".tgz"]):
            is_tar_file = True

        if is_tar_file:
            with tarfile.open(name=file, mode="r:gz", encoding="utf-8") as tar:
                device_info["existing_files"] = []
                for member in tar.getmembers():
                    device_info["existing_files"].append(member.name)
                    f_handle = tar.extractfile(member)

                    if f_handle:
                        path = PurePath(member.name)
                        sage_parse.parse_file(path, f_handle, device_info)
                    else:
                        cls.log.trace3(
                            f"Failed to extract {member.name} (it's probably a directory)"
                        )
        elif file.is_dir():
            device_info["existing_files"] = []

            for root, _, filenames in os.walk(str(file)):
                for filename in filenames:
                    path = Path(root, filename).resolve()
                    path_str = path.as_posix()

                    # Ignore /ata0a/backup/* and /ata0a/recovery/ directories
                    if "/backup/" in path_str or "/recovery/" in path_str:
                        continue

                    relative_path = path_str[path_str.find(file.name) :]
                    device_info["existing_files"].append(relative_path)

                    with path.open("rb") as f_handle:
                        sage_parse.parse_file(path, f_handle, device_info)
        else:
            # Parse a specific file, e.g. "rtusetup.xml"
            with file.open("rb") as f_handle:
                if not sage_parse.parse_file(file, f_handle, device_info):
                    raise ParseError(f"No valid Sage parser for '{file.name}'")

        # TODO: refactor parsing functions to return dicts/lists,
        # then call .update() on device_info with the result
        # It's cleaner, and makes unit testing much easier

        # Sort data for consistency
        device_info = utils.sort(device_info)

        # Save the raw data to a temporary file for debugging purposes
        td_pth = utils.write_temp_file(device_info, "sage_raw-device-info.json")

        bootline = device_info.get("bootline_from_xml")

        # Try to find the IP from bootline info to construct a DeviceData object
        if bootline and bootline.get("ethernet_ip"):
            ip = bootline["ethernet_ip"]
            if not dev:
                dev = datastore.get(ip)

            iface = Interface(
                ip=ip,
                subnet_mask=bootline.get("ethernet_subnet_mask", ""),
                gateway=bootline.get("gateway_ip", ""),
                type="ethernet",
            )
            dev.store("interface", iface)
        elif not dev:
            # If there's no IP, use the filename as the device ID
            # This may happen with static configs, e.g. from firmware update configs
            file_basename = file.stem.replace(".tar", "").replace(".gz", "")
            dev = datastore.get(file_basename, "id")

        if device_info.get("rtusetup_info"):
            sage_parse.process_rtusetup_info(dev, device_info["rtusetup_info"])
            dev.extra["rtusetup_info"] = device_info["rtusetup_info"]

        if device_info.get("access_info"):
            sage_parse.process_access_xml(dev, device_info["access_info"])
            dev.extra["access_info"] = device_info["access_info"]

        if bootline:
            sage_parse.process_bootline(dev, bootline)
            dev.extra["bootline_from_xml"] = bootline

        if device_info.get("ipcom_syslog_events"):
            sage_parse.process_ipcom_syslog(dev, device_info["ipcom_syslog_events"])
            dev.write_file(
                data=device_info["ipcom_syslog_events"],
                filename="raw-ipcom-syslog-events.json",
            )

        if device_info.get("raw_events"):
            sage_parse.process_logfile_events(dev, device_info["raw_events"])
            dev.write_file(device_info["raw_events"], "raw-events.json")

        # TODO: add more stuff to dev.extra
        # TODO: nest most of the config XML files under a "zzz_parsed_xml_configs" key
        # TODO: add SSH keys to data model

        if device_info.get("vxworks_script"):
            dev.extra["vxworks_startup_script"] = device_info["vxworks_script"]

        # TODO: extract SSL certificates and private keys
        #   parse into data model, use code from http module
        # cert/key-related Fields in the parsed data:
        #   device_info["ike"]["cert"]
        #   device_info["ike"]["telvent_cert_auth"]
        #   device_info["server_certificate"]
        #   device_info["ike"]["privkey"]
        #   device_info["server_private_key"]

        # Infer and populate fields in data model
        cls.update_dev(dev)

        if is_tar_file or file.is_dir():
            dev.write_file(device_info, "parsed-config.json")
        else:
            dev.write_file(device_info, f"{file.stem}-parsed-config.json")

        # TODO: store tar file metadata: path, hash, size, owner, timestamp
        if is_tar_file:
            dev.related.files.add(file.name)

        # Add all filenames to dev.related.files
        # TODO: store file metadata: path, hash, size, owner, timestamp
        if device_info.get("existing_files"):
            for file_path in device_info["existing_files"]:
                if not file_path.endswith("/"):
                    dev.related.files.add(PurePath(file_path).name)

        # TODO: set boot_firmware to "vxworks" file, if pulled

        # Extract the raw files from the tarball to the device results directory
        if is_tar_file and config.DEVICE_DIR:
            try:
                if td_pth:
                    utils.move_file(td_pth, dev.get_out_dir())

                file_basename = file.stem.replace(".tar", "").replace(".gz", "")
                t_path = dev.get_sub_dir(f"{file_basename}_raw_files")

                cls.log.debug(
                    f"Extracting raw files from {file.name} to {t_path.parent.name}/{t_path.name}"
                )

                with tarfile.open(name=file, mode="r:gz", encoding="utf-8") as tar:
                    tar.extractall(path=t_path)
            except Exception as ex:
                cls.log.debug(f"Failed to extract raw files from {file.name}: {ex}")

        return dev


Sage.ip_methods = [
    IPMethod(
        name="Sage FTP login",
        description=str(Sage._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=Sage._verify_ftp,
        reliability=7,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    ),
    IPMethod(
        name="Sage Telnet login",
        description=str(Sage._verify_protocol.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Sage._verify_protocol, protocol="telnet"),
        reliability=6,
        protocol="telnet",
        transport="tcp",
        default_port=23,
    ),
    IPMethod(
        name="Sage SSH login",
        description=str(Sage._verify_protocol.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Sage._verify_protocol, protocol="ssh"),
        reliability=6,
        protocol="ssh",
        transport="tcp",
        default_port=22,
    ),
    IPMethod(
        name="Sage SSL certificate",
        description=str(Sage._verify_https_ssl_certificate.__doc__).strip(),
        type="unicast_ip",
        identify_function=Sage._verify_https_ssl_certificate,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="Sage HTTP page scrape",
        description=str(Sage._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Sage._verify_http, protocol="http"),
        reliability=8,
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="Sage HTTPS page scrape",
        description=str(Sage._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Sage._verify_http, protocol="https"),
        reliability=8,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
]


__all__ = ["Sage"]
