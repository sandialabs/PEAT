"""
iDirect X-series modems (X3, X5, X7).

Authors

- Christopher Goes
"""

import functools
import json
from configparser import ConfigParser
from pathlib import PurePosixPath
from typing import Literal

from paramiko.ssh_exception import AuthenticationException

from peat import DeviceData, DeviceModule, IPMethod, exit_handler, log, state, utils
from peat.data.data_utils import merge_models
from peat.parsing.command_parsers import (
    ArpParser,
    DateParser,
    EnvParser,
    EtcPasswdParser,
    HostnameParser,
    IfconfigParser,
    LsRecursiveParser,
    NixParserBase,
    ProcCmdlineParser,
    ProcCpuinfoParser,
    ProcMeminfoParser,
    ProcModulesParser,
    ProcNetDevParser,
    ProcUptimeParser,
    SshdConfigParser,
    VarLogMessagesParser,
    convert_filename,
)
from peat.protocols import HTTP

from .idirect_ssh import IdirectSSH

IDIRECT_PARSERS: list[type[NixParserBase]] = [
    # NOTE: DateParser needs to run before VarLogMessagesParser
    DateParser,
    VarLogMessagesParser,
    ProcCmdlineParser,
    ProcCpuinfoParser,
    ProcMeminfoParser,
    ProcModulesParser,
    ProcUptimeParser,
    EtcPasswdParser,
    EnvParser,
    IfconfigParser,
    ArpParser,
    SshdConfigParser,
    HostnameParser,
    ProcNetDevParser,
    LsRecursiveParser,
]


class Idirect(DeviceModule):
    """
    iDirect X-series modems (X3, X5, X7).
    """

    device_type = "Modem"
    vendor_id = "iDirect"
    # ST Engineering iDirect, Inc.?
    vendor_name = "iDirect, Inc."
    # TODO: implement "peat parse" API for Idirect
    # filename_patterns = [
    #     "falcon.opt",
    #     "idirect-release",
    # ]
    module_aliases = ["idirect-x3", "idirect-x5", "idirect-x7"]
    default_options = {
        "idirect": {
            "pull_methods": [
                "ssh",
                "ssl",
            ],
        },
        "ssh": {
            "user": "",
            "pass": "",
            "creds": [
                ("root", "iDirect"),
            ],
        },
        "telnet": {
            "user": "",
            "pass": "",
            "creds": [],
        },
    }

    @classmethod
    def _login_ssh(cls, dev: DeviceData) -> IdirectSSH | None:
        if dev.options["ssh"]["user"] and dev.options["ssh"]["pass"]:
            creds = [(dev.options["ssh"]["user"], dev.options["ssh"]["pass"])]
        else:
            creds = dev.options["ssh"]["creds"]  # type: list[tuple[str, str]]

        for username, password in creds:
            try:
                conn = IdirectSSH(
                    ip=dev.ip,
                    port=dev.options["ssh"]["port"],
                    timeout=dev.options["ssh"]["timeout"],
                    username=username,
                    password=password,
                )

                if conn.test_connection():
                    dev.options["ssh"]["user"] = username
                    dev.options["ssh"]["pass"] = password
                    return conn
            except AuthenticationException:
                pass

        return None

    @classmethod
    def _verify_protocol(
        cls, dev: DeviceData, protocol: Literal["ssh", "telnet"] = "telnet"
    ) -> bool:
        """
        Verify if the given protocol can connect to the iDirect modem.

        !! NOTE: Telnet is not yet implemented !!

        Args:
            dev: Device specific data and configuration.
            protocol: Which protocol to use (telnet or ssh).

        Returns:
            Check if a device is a iDirect modem by logging in.
        """

        if protocol not in ["ssh", "telnet"]:
            raise ValueError("Protocol {protocol} not supported!")
        if protocol == "telnet":
            raise NotImplementedError("telnet verify isn't implemented yet")

        try:
            conn = cls._login_ssh(dev)

            if not conn:
                cls.log.debug(
                    f"Failed {protocol.capitalize()} verify for {dev.ip}: connection failed"
                )
                conn.disconnect()
                return False

            dev.related.user.add(dev.options[protocol]["user"])

            successful = False
            if protocol == "ssh":
                conn.read()
                if any(" iDirect " in x for x in conn.all_output):
                    successful = True
                else:
                    # This method takes ~6 seconds total, vs ~1 second
                    # for just checking the prompt from connecting.
                    conn.write("ls /sysopt/factory/")
                    ls_res = conn.read()
                    if "falcon" in ls_res:
                        successful = True

            if not successful:
                cls.log.debug(f"Failed {protocol.capitalize()} verify for {dev.ip}")
                conn.disconnect()
                return False

            # Cache the session for use in _pull_protocol(), and ensure
            # the connection is closed properly when PEAT exits.
            dev._cache[f"idirect_{protocol}_session"] = conn
            exit_handler.register(
                dev._cache[f"idirect_{protocol}_session"].disconnect, "CONNECTION"
            )
            dev._cache[f"idirect_{protocol}_fingerprinted"] = True

            return True
        except Exception as ex:
            cls.log.trace(
                f"Failed {protocol.capitalize()} verify due to exception: {ex}"
            )
            conn.disconnect()
            return False

    @classmethod
    def _verify_https_ssl_certificate(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a iDirect modem via HTTPS SSL certificate inspection.
        """
        timeout = dev.options["https"]["timeout"]
        port = dev.options["https"]["port"]

        cls.log.debug(f"Verifying {dev.ip}:{port} using HTTPS SSL (timeout: {timeout})")

        with HTTP(dev.ip, port, timeout) as http:
            cert = http.get_ssl_certificate()

        if not cert:
            return False

        merge_models(dev.x509, cert)

        entity = cert.subject
        if not entity.organization:
            entity = cert.issuer
        if not entity.organization:
            cls.log.debug(
                f"No 'subject' or 'issuer' in HTTPS SSL certificate from {dev.ip}"
            )
            return False

        dev._cache["idirect_ssl_fingerprinted"] = True

        if entity.organization.startswith("iDirect") or any(
            "idirect.net" in an for an in cert.alternative_names
        ):
            cls.log.debug(f"HTTPS SSL verification successful for {dev.ip}:{port}")
            return True

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        pull_successful = False

        # ** Telnet/SSH pulling **
        for pull_type in ["ssh"]:
            pull_type_cap = pull_type.capitalize()
            if pull_type not in dev.options["sage"]["pull_methods"]:
                cls.log.warning(
                    f"Skipping method '{pull_type_cap}' for pull from {dev.ip}: "
                    f"'{pull_type_cap}' not listed in 'sage.pull_methods' option"
                )
            elif (
                dev.service_status(
                    {"protocol": pull_type, "port": dev.options[pull_type]["port"]}
                )
                == "closed"
            ):
                cls.log.warning(
                    f"Failed to pull {pull_type_cap} on {dev.ip}: "
                    f"{pull_type_cap} service is closed"
                )
            elif not dev._cache.get(
                f"idirect_{pull_type}_fingerprinted"
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

                if pull_type == "ssh":
                    pull_successful = cls._pull_ssh(dev)
                else:
                    raise NotImplementedError(f"{pull_type} not implemented")

        # ** SSL certificate pulling **
        # pull https cert info as well if it wasn't scanned
        if "ssl" not in dev.options["idirect"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'ssl' for pull from {dev.ip}: "
                f"'ssl' not listed in 'idirect.pull_methods' option"
            )
        elif (
            dev.service_status(
                {"protocol": "https", "port": dev.options["https"]["port"]}
            )
            == "closed"
        ):
            cls.log.warning(f"Failed to pull SSL on {dev.ip}: HTTPS service is closed")
        elif not dev._cache.get(
            "idirect_ssl_fingerprinted"
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

        return pull_successful

    @classmethod
    def _pull_ssh(cls, dev: DeviceData) -> bool:
        """
        Pulls information via SSH.

        Args:
            dev: Device specific data and configuration.

        Returns:
            If pull was successful
        """

        timeout = dev.options["ssh"]["timeout"]  # type: float
        port = dev.options["ssh"]["port"]  # type: int

        cls.log.info(f"Pulling from {dev.ip}:{port} using SSH (timeout: {timeout})")

        # Reuse an existing telnet/ssh session from _verify_protocol(),
        # or a previous pull in the same run.
        #
        # NOTE: a "with" statement isn't used here to allow PEAT to preserve the
        # session if successfully verified for use in _pull_protocol().
        conn = dev._cache.get("idirect_ssh_session")  # type: Optional[IdirectSSH]
        if not conn:
            conn = IdirectSSH(
                ip=dev.ip,
                port=port,
                timeout=timeout,
                username=dev.options["ssh"]["user"],
                password=dev.options["ssh"]["pass"],
            )
            dev._cache["idirect_ssh_session"] = conn
            exit_handler.register(
                dev._cache["idirect_ssh_session"].disconnect, "CONNECTION"
            )
            conn.test_connection()
            conn.read()
            dev.related.user.add(dev.options["ssh"]["user"])

        # TODO: get and parse public and private SSH keys in /etc/ssh/

        # TODO: use "find" command to look for falcon.opt
        #   cache location once it's found.
        # !! TODO: find all .opt files to get ones with different names

        # TODO: netstat parsing, grab ports

        # TODO: files
        #   add host.files
        #   add file hashes from find command to file objects
        #   add file.original for the files that do get pulled

        # TODO: fix ifconfig, ensure interfaces getting into data model

        # TODO: ip route
        #   host.routes
        #   host.connections

        # exit with error if important files fail to pull or parse
        allowed_failures = [
            FalconOptParser,
        ]
        successful = True

        for parser in IDIRECT_PARSERS:
            # TODO: only LS certain parts of file system to add to model?
            # if parser is LsRecursiveParser:
            #     pass
            #     continue

            # !! TODO: can put multiple paths in LS command, don't need to do everything
            # ls -lenAR /sysopt /common /etc/ /var/log /tmp /root

            # TODO: generalize this for parsers with multiple files/commands
            if parser.file:
                cls.log.info(f"Reading and parsing file: {parser.file}")
                data = conn.write_read(f"cat {parser.file!s}")

                if not data or "No such file or directory" in data:
                    cls.log.error(f"No data from file {parser.file!s}")
                    if parser not in allowed_failures:
                        state.error = True
                        successful = False
                    continue
            else:
                cls.log.info(f"Running and parsing command: {parser.command}")
                data = conn.write_read(parser.command)

                if not data:
                    cls.log.error(f"No data from command: {parser.command}")
                    if parser not in allowed_failures:
                        state.error = True
                        successful = False
                    continue

            if not parser.parse_and_process(data, dev):
                cls.log.warning(f"Failed {parser.type()} parse and process on {dev.ip}")

        # TODO: pull whole directories of files
        #   /sysopt/config/
        # Additional files that don't have parsers yet
        extra_files = [
            "/var/log/dmesg",
            "/sysopt/config/network/beam_map.json",
            "/etc/idirect-release",  # TODO: implement parser
            "/proc/version",  # TODO: implement parser
        ]
        for filepath in extra_files:
            cls.log.info(f"Reading file: {filepath}")
            try:
                file_data = conn.write_read(f"cat {filepath}")

                if file_data and "No such file or directory" not in file_data:
                    dev.related.files.add(filepath)

                    path_obj = PurePosixPath(filepath)

                    # PEAT's auto-serialization of JSON works against
                    # us here, so manually load it then save.
                    if path_obj.suffix == ".json":
                        file_data = json.loads(file_data)

                    dev.write_file(
                        data=file_data,
                        filename=path_obj.name,
                        out_dir=dev.get_out_dir() / "raw_files",
                    )

                    if filepath in [
                        "/etc/idirect-release",
                        "/proc/version",
                    ]:
                        dev.extra[filepath] = file_data
                else:
                    cls.log.warning(f"No data from file {filepath}")
            except Exception as ex:
                cls.log.warning(f"Failed to read file {filepath}: {ex}")

        # Additional commands that don't have parsers yet
        extra_commands = [
            # Shows all active network connections
            "netstat -tulnp",
            "uname -a",
            "ip addr",
            "ip route",
            "df",
            "fdisk -l",
            "id",
            # TODO: do for multiple dirs
            # /etc
            # /boot
            # /var/log
            # /root
            # /sysopt
            # /sbin
            # /pkg
            # /bin
            # /common
            # /opt
            # /lib
            # /usr
            # TODO: Implement as parser
            "find /etc /var/log /root /sysopt /pkg /common /opt -type f -exec sha256sum {} \\;",
        ]

        # TODO: need to increase ssh delay for long-running commands...

        for command in extra_commands:
            cls.log.info(f"Running command: {command}")
            try:
                # run cmd
                cmd_result = conn.write_read(command)

                if cmd_result:
                    # !! hack !!
                    if command.startswith("find"):
                        cmd_result = cmd_result.replace("\\;", "").strip()

                    # save to file
                    dev.write_file(
                        data=cmd_result,
                        filename=convert_filename(command) + ".txt",
                        out_dir=dev.get_out_dir() / "raw_commands",
                    )

                    if command in [
                        "netstat -tulnp",
                        "uname -a",
                        "ip addr",
                        "ip route",
                        "id",
                    ]:
                        dev.extra[command] = cmd_result
                else:
                    cls.log.warning(f"No data from command: {command}")
            except Exception as ex:
                cls.log.warning(f"Failed command '{command}': {ex}")

        cls.log.info(f"Finished pulling from {dev.ip}:{port} using SSH")
        cls.update_dev(dev)

        return successful

    # TODO: implement parsing for Idirect
    # @classmethod
    # def _parse(
    #     cls, file: Path, dev: Optional[DeviceData] = None
    # ) -> Optional[DeviceData]:
    #     # "file" can be one of the following:
    #     # - falcon.opt
    #     # - idirect-release

    #     raw_data = file.read_bytes()
    #     f_name = file.name.lower()


class FalconOptParser(NixParserBase):
    """
    Parse the contents of ``falcon.opt`` into a dict.
    This is usually located in ``/sysopt/config/sat_router/falcon.opt``.
    """

    # TODO: *.opt extension
    file = PurePosixPath("/sysopt/config/sat_router/falcon.opt")
    files = [file]

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, dict[str, str]]:
        parser = ConfigParser()
        parser.read_string(to_parse)

        results = {s.lower(): dict(parser[s]) for s in parser.sections()}

        return results

    @classmethod
    def process(cls, to_process: dict[str, dict[str, str]], dev: DeviceData) -> None:
        for section_name, section_value in to_process.items():
            for key, value in section_value.items():
                try:
                    if key.endswith("_port"):
                        port = int(value)
                        if port:  # not 0
                            dev.related.ports.add(port)
                    elif (
                        "netmask" not in key
                        and utils.is_ip(value)
                        and not value.startswith("255.")
                        and not value.startswith("0.")
                    ):
                        dev.related.ip.add(value)

                    # TODO: SAT0_1

                    # TODO: ROUTE_1_0

                    # TODO: ETH0 and ETH0_1

                except Exception as ex:
                    log.warning(
                        f"Failed to parse key '{key}' in "
                        f"falcon_opt section '{section_name}': {ex}"
                    )


# Add parser and processor for falcon.opt to the collection of parsers
IDIRECT_PARSERS.append(FalconOptParser)


Idirect.ip_methods = [
    # TODO: telnet fingerprinting for iDirect
    # IPMethod(
    #     name="Idirect Telnet login",
    #     description=str(Idirect._verify_protocol.__doc__).strip(),
    #     type="unicast_ip",
    #     identify_function=functools.partial(
    #         Idirect._verify_protocol, protocol="telnet"
    #     ),
    #     reliability=6,
    #     protocol="telnet",
    #     transport="tcp",
    #     default_port=23,
    # ),
    IPMethod(
        name="Idirect SSH login",
        description=str(Idirect._verify_protocol.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Idirect._verify_protocol, protocol="ssh"),
        reliability=6,
        protocol="ssh",
        transport="tcp",
        default_port=22,
    ),
    IPMethod(
        name="Idirect HTTPS SSL certificate",
        description=str(Idirect._verify_https_ssl_certificate.__doc__).strip(),
        type="unicast_ip",
        identify_function=Idirect._verify_https_ssl_certificate,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
]


__all__ = ["Idirect"]
