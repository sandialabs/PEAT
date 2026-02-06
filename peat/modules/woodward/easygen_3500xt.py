"""
easYgen 3500XT pulling and parsing functionality,

Pull is done using FTP and ServLink/TCP.
Most of config pulled from Servlink, a variant of Modbus-TCP, over port 666.
Pulling mimics the Woodward Toolkit storage which saves config into wset file.

Authors

- Christopher Goes
- Ryan Vrecenar
"""

import functools
from pathlib import Path

from peat import (
    DeviceData,
    DeviceError,
    DeviceModule,
    Interface,
    IPMethod,
    SerialMethod,
    datastore,
)
from peat.protocols import FTP, check_tcp_port, open_serial_port, pretty_hex_bytes

from .easygen_svl import (
    SVL_DATA_DELIM,
    SVLSER_INIT_ACK,
    SVLSER_INIT_MSG,
    SVLTCP_INIT_ACK,
    SVLTCP_INIT_MSG,
    svl_dat_prms,
)
from .parse_wset import parse_wset

# from . import parse_micronet
from .wdw_svl import (
    _svl_parse_data,
    _svlser_dat_txn,
    _svlser_raw_txn,
    _svlser_sys_txn,
    _svltcp_dat_txn,
    _svltcp_init,
    _svltcp_sys_txn,
    svl_socket_initialized,
    svl_sys_cmds,
)

easygen_data_types: dict[str, dict] = {
    "prm_am": {"mask": b"\x0a", "len": 16},
    "prm_lm": {"mask": b"\x0a", "len": 16},
    "ezg_0a": {"mask": b"\x0a", "len": 0},
    "ezg_00": {"mask": b"\x00", "len": 0},
}


# TODO for woodward
# - Integrate *.tc parsing
# - Add data to PEAT data model


class Easygen3500XT(DeviceModule):
    device_type = "Genset Controller"  # Engine/Generator control and protector
    vendor_id = "Woodward"
    vendor_name = "Woodward, Inc"
    brand = "easYgen"
    model = "3500XT"
    # TODO: should wset and tc parsing belong here or 3500XT?
    filename_patterns = ["*.wset", "*.tc"]
    # TODO: combine some common functions of 3500XT and 2301E?
    easygen_fallback_baudrates = [9600]
    default_options = {
        "woodward": {
            "pull_methods": [
                "servlink_tcp",
                "ftp",
            ]
        },
        "ftp": {
            "user": "CL01",
            "pass": "CL0001",
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

                # TODO: verify using file listing?
                # -> use ftp.find_file()

                if "/ram" not in pwd.lower():
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: current directory is not /ram/"
                    )
                    return False

                dev._cache["easygen_ftp_fingerprinted"] = True
        except Exception as ex:
            cls.log.debug(f"Failed to verify {dev.ip} via FTP: {ex}")
            return False
        cls.log.debug(f"Verified {dev.ip}:{port} via FTP")
        return True

    @classmethod
    def _verify_servlink(cls, dev: DeviceData, port: int = 666) -> bool:
        """
        Verify if a device is a easyYgen 3500 via the
        Woodward-proprietary Servlink/TCP protocol.
        """
        if dev.options["servlink_tcp"]["port"] != 666 and port == 666:
            port = dev.options["servlink_tcp"]["port"]
        timeout = dev.options["servlink_tcp"]["timeout"]

        cls.log.debug(f"Verifying Servlink/TCP for {dev.ip}:{port} (timeout: {timeout})")

        if (
            _svltcp_init(dev.ip, SVLTCP_INIT_MSG) == SVLTCP_INIT_ACK
            and "eg3500" in str(_easygen_tcp_sys_txn(dev.ip, svl_sys_cmds["Application"])).lower()
        ):
            if not dev._runtime_options.get("servlink_tcp"):
                dev._runtime_options["servlink_tcp"] = {}
            dev._runtime_options["servlink_tcp"]["port"] = port
            dev._cache["servlink_fingerprinted"] = True
            cls.log.info(f"Servlink/TCP verification successful for {dev.ip}:{port}")
            return True

        cls.log.debug(f"Servlink/TCP verification failed for {dev.ip}:{port}")
        return False

    @classmethod
    def _verify_serial(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a easYgen 3500XT via the Woodward-proprietary Servlink
        protocol over a serial connection.
        """
        baudrates = dev.options["baudrates"]
        if not baudrates:
            baudrates = cls.easygen_fallback_baudrates
        timeout = dev.options["servlink_serial"]["timeout"]

        for baudrate in baudrates:
            # TODO: if _svlser_raw_txn() is successful, but string check fails, it may be a 2301E
            #   We should try to avoid duplication of work somehow.
            if (
                open_serial_port(dev.serial_port, baudrate, timeout)
                and _svlser_raw_txn(dev.serial_port, SVLSER_INIT_MSG, True) == SVLSER_INIT_ACK
                and "eg3500"
                in str(_easygen_ser_sys_txn(dev.serial_port, svl_sys_cmds["Application"])).lower()
            ):
                cls.log.debug(f"Verified {dev.serial_port} (baudrate: {baudrate})")
                iface = Interface(
                    connected=True,
                    type="rs_232",  # TODO: detect serial interface type
                    serial_port=dev.serial_port,
                    baudrate=baudrate,
                    parity="none",
                    stop_bits=1,
                    flow_control="none",
                )
                dev.store("interface", iface, lookup="serial_port")
                return True

        cls.log.warning(f"Failed to verify {dev.serial_port} (baudrates: {baudrates})")
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        pull_successful = False

        # Serial pull
        if dev.serial_port and dev.retrieve("interface", {"type": "serial", "connected": True}):
            serial_info = cls._get_serial_data(dev.serial_port)
            if serial_info:
                pull_successful = True
                dev.write_file(serial_info, "serial-info.json")
                dev.extra.update(serial_info)

        # TODO: hack to fix "verified" status
        #   this should be addressed more generally in peat
        #   See the Sage code for details

        # IP pull
        elif dev.ip:
            # ** ServLink/TCP **
            if "servlink_tcp" not in dev.options["woodward"]["pull_methods"]:
                cls.log.warning(
                    f"Skipping method 'servlink_tcp' for pull from {dev.ip}: "
                    f"'servlink_tcp' not listed in 'woodward.pull_methods' option"
                )
            elif (
                dev.service_status(
                    {
                        "protocol": "servlink_tcp",
                        "port": dev.options["servlink_tcp"]["port"],
                    }
                )
                == "closed"
            ):
                cls.log.warning(
                    f"Failed to pull Servlink/TCP on {dev.ip}: Servlink/TCP service is closed"
                )
            elif not dev._cache.get("servlink_fingerprinted") and not cls._verify_servlink(dev):
                cls.log.warning(
                    f"Failed to pull Servlink/TCP on {dev.ip}: Servlink/TCP verification failed"
                )
            else:
                servlink_info = cls._get_svl_tcp_data(dev.ip)
                pull_successful = bool(servlink_info)
                if servlink_info:
                    dev.write_file(servlink_info, "servlink-info.json")
                    dev.extra.update(servlink_info)
                cls.update_dev(dev)
                # TODO: pull servlink data to .wset file, then parse the .wset file

            # ** FTP **
            if "ftp" not in dev.options["woodward"]["pull_methods"]:
                cls.log.warning(
                    f"Skipping method 'ftp' for pull from {dev.ip}: "
                    f"'ftp' not listed in 'woodward.pull_methods' option"
                )
            elif (
                dev.service_status({"protocol": "ftp", "port": dev.options["ftp"]["port"]})
                == "closed"
            ):
                cls.log.warning(f"Failed to pull FTP on {dev.ip}: FTP service is closed")
            elif not dev._cache.get("easygen_ftp_fingerprinted") and not cls._verify_ftp(dev):
                cls.log.warning(f"Failed to pull FTP on {dev.ip}: FTP verification failed")
            else:
                # TODO: preserve FTP session between verify and pull
                cls._pull_ftp(dev)
                pull_successful = True
        else:
            cls.log.error(
                f"Failed pulling project from {dev.address}: "
                f"no serial interface connected or no IP set"
            )

        return pull_successful

    @classmethod
    def _pull_ftp(cls, dev: DeviceData) -> bool:
        timeout = dev.options["ftp"]["timeout"]
        port = dev.options["ftp"]["port"]

        cls.log.info(f"Pulling from {dev.ip}:{port} using FTP (timeout: {timeout})")

        with FTP(dev.ip, port, timeout) as ftp:
            username = dev.options["ftp"]["user"]
            password = dev.options["ftp"]["pass"]

            ftp.login(username, password)
            dev.related.user.add(username)

            ftp_dir = dev.get_sub_dir("ftp_files")

            if ftp.pwd() != "/":
                ftp.cd("..")

            listing = ftp.rdir()
            if not listing:
                cls.log.error("Failed to pull FTP files: 'dir' commands failed")
                return False

            dev.write_file(listing[1], "ftp-file-listing.json")

            ftp.download_files(local_dir=ftp_dir, files=listing[1])

        # TODO: return list of files pulled + file listing information
        # TODO: record file metadata: permissions, size, flags, modification timestamp

        # TODO: dev.related.files
        # TODO: return what files were pulled
        # TODO: return failure if there were any critical errors during pull
        # TODO: combine common functionality with Sage

        # TODO: parsers
        #   OS/keys/pkey_db/default_*
        #   OS/System/FirewallRulesIPv4.cfg  (get interface names?)
        #   Hashes of files
        #   Other work
        #       *.ee and *.nlg
        #       HD1FX/Logs/Log.txt => parse_micronet.parse_log()
        #       HD1FX/Logs/PMLog.* (.txt and .old)
        #           - parse into dev.event
        #           - add to dev.users and dev.related.users
        #       HD1FX/Logs/SysLog.txt
        #       HD1FX/Logs/LogFile.txt
        #       -- Hashing of files that jon did e.g. for vxWorks and VxService.out --
        #       Extraction of firmware info from vxWorks binary headers
        #       Generalize some of this into a VxWorks-general library?
        #           (e.g. parsing of vxWorks file)

        cls.log.info(f"Finished pulling from {dev.ip}:{port} using FTP")

        return True

    @classmethod
    def _get_serial_data(cls, serial_port: str) -> dict[str, str]:
        """
        Get the system information and configuration using Servlink serial.
        It is assumed that the serial connection has been opened and the
        Servlink sequence has been reset previously e.g. in ``_verify_serial()``.

        Args:
            serial_port: The serial port

        Returns:
            A dictionary containing the system information
        """
        cls.log.info(f"Pulling Servlink serial information from {serial_port}")
        serial_info = {"system": {}, "config": {}}  # type: dict[str, Any]

        # Get the system information
        for k in svl_sys_cmds.keys():
            cls.log.debug("Pulling System\\%s", k)
            serial_info["system"][k] = _easygen_ser_sys_txn(serial_port, svl_sys_cmds[k])
            cls.log.trace2(f'{k} = "{serial_info["system"][k]}"')

        # Get the configuration
        for k in svl_dat_prms.keys():
            cls.log.debug("Pulling %s", k)
            serial_info["config"][k] = _easygen_ser_dat_txn(serial_port, svl_dat_prms[k])
            cls.log.trace2(f'{k} = "{serial_info["config"][k]}"')

        if not serial_info["system"]:
            del serial_info["system"]
        if not serial_info["config"]:
            del serial_info["config"]

        cls.log.info(f"Finished pulling Servlink serial information from {serial_port}")
        return serial_info

    @classmethod
    def _get_svl_tcp_data(cls, ip: str) -> dict[str, str]:
        """
        Get the system information and configuration using Servlink serial.
        It is assumed that the serial connection has been opened and the
        Servlink sequence has been reset previously e.g. in ``_verify_serial()``.

        Args:
            ip: The IP address

        Returns:
            A dictionary containing the system information
        """
        cls.log.info(f"Pulling Servlink/TCP information from {ip}")
        svl_info = {"system": {}, "config": {}}  # type: dict[str, Any]

        # TODO: pull config to wset file, easygen_enums.MESSAGE_QUEUE

        if not svl_socket_initialized(ip):
            _svltcp_init(ip, SVLTCP_INIT_MSG)

        # Get the system information
        for k in svl_sys_cmds.keys():
            cls.log.debug("Pulling System\\%s", k)
            svl_info["system"][k] = _easygen_tcp_sys_txn(ip, svl_sys_cmds[k])
            cls.log.trace2(f'{k} = "{svl_info["system"][k]}"')

        # Get the configuration
        for k in svl_dat_prms.keys():
            cls.log.debug("Pulling %s", k)
            svl_info["config"][k] = _easygen_tcp_dat_txn(ip, svl_dat_prms[k])
            cls.log.trace2(f'{k} = "{svl_info["config"][k]}"')

        if not svl_info["system"]:
            del svl_info["system"]
        if not svl_info["config"]:
            del svl_info["config"]

        cls.log.info(f"Finished pulling Servlink/TCP information from {ip}")
        return svl_info

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        if file.suffix.lower() == ".tc":
            raise DeviceError(f"*.tc files are not currently supported (filename: '{file.name}')")

        parsed_config = parse_wset(file)

        if not dev:
            dev = datastore.get(file.stem, "id")

        dev.write_file(parsed_config, "parsed-config.json")

        return dev


def easygen_port_check(dev: DeviceData, port: int) -> bool:
    """Function to set the TCP RST flag for Servlink/TCP scanning."""
    return check_tcp_port(dev.ip, port, reset=True)


Easygen3500XT.ip_methods = [
    IPMethod(
        name="Woodward easYgen FTP",
        description=str(Easygen3500XT._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=Easygen3500XT._verify_ftp,
        reliability=5,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    ),
    IPMethod(
        name="Woodward Servlink/TCP",
        description=str(Easygen3500XT._verify_servlink.__doc__).strip(),
        type="unicast_ip",
        identify_function=Easygen3500XT._verify_servlink,
        reliability=7,
        protocol="servlink_tcp",
        transport="tcp",
        default_port=666,
        port_function=functools.partial(easygen_port_check, port=666),
    ),
    IPMethod(
        name="Woodward Servlink/TCP alt port 667",
        description=str(Easygen3500XT._verify_servlink.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Easygen3500XT._verify_servlink, port=667),
        reliability=7,
        protocol="servlink_tcp",
        transport="tcp",
        default_port=667,
        port_function=functools.partial(easygen_port_check, port=667),
    ),
]


Easygen3500XT.serial_methods = [
    SerialMethod(
        name="Servlink serial verification",
        description=str(Easygen3500XT._verify_serial.__doc__).strip(),
        type="direct",
        identify_function=Easygen3500XT._verify_serial,
        reliability=6,
    )
]


def _easygen_ser_sys_txn(address: str, sys_cmd_itm: dict):
    ser_rsp = _svlser_sys_txn(address, sys_cmd_itm)
    return _svl_parse_data(ser_rsp["rbytes"], sys_cmd_itm["type"])


def _easygen_ser_dat_txn(address: str, dat_cmd_itm: dict):
    if dat_cmd_itm["type"] in easygen_data_types:
        ser_rsp = _svlser_dat_txn(
            address,
            dat_cmd_itm,
            easygen_data_types[dat_cmd_itm["type"]]["mask"],
            SVL_DATA_DELIM,
        )
        return _easygen_parse_data(ser_rsp["rbytes"], dat_cmd_itm["type"])
    else:
        ser_rsp = _svlser_dat_txn(address, dat_cmd_itm, None, SVL_DATA_DELIM)
        return _svl_parse_data(ser_rsp["rbytes"], dat_cmd_itm["type"])


def _easygen_tcp_sys_txn(ip: str, sys_cmd_itm: dict):
    tcp_rsp = _svltcp_sys_txn(ip, sys_cmd_itm)
    return _svl_parse_data(tcp_rsp["rbytes"], sys_cmd_itm["type"])


def _easygen_tcp_dat_txn(ip: str, dat_cmd_itm: dict) -> str:
    if dat_cmd_itm["type"] in easygen_data_types:
        tcp_rsp = _svltcp_dat_txn(
            ip,
            dat_cmd_itm,
            easygen_data_types[dat_cmd_itm["type"]]["mask"],
            SVL_DATA_DELIM,
        )
        return _easygen_parse_data(tcp_rsp["rbytes"], dat_cmd_itm["type"])
    else:
        tcp_rsp = _svltcp_dat_txn(ip, dat_cmd_itm, None, SVL_DATA_DELIM)
        return _svl_parse_data(tcp_rsp["rbytes"], dat_cmd_itm["type"])


def _easygen_parse_data(data_bytes: bytes, rfmt: type) -> str:
    rfmt_len = easygen_data_types[rfmt]["len"]
    if rfmt_len != 0 and len(data_bytes) != rfmt_len:
        return pretty_hex_bytes(data_bytes)

    # Parse the data
    if rfmt == "prm_am":
        rstr = ""
        i = int.from_bytes(data_bytes[2:4], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Analog1="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[4:6], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Analog2="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[6:8], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Logic1="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[8:10], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Logic2="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[14:15], "big", signed=False)
        rstr += str.format(f'Operators="{i}" ')
        return rstr + str.format(f'RawBytes="{pretty_hex_bytes(data_bytes)}"')
    if rfmt == "prm_lm":
        rstr = ""
        i = int.from_bytes(data_bytes[10:12], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Input1="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[12:14], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Input2="{s[:2]}.{s[2:]}" ')
        i = int.from_bytes(data_bytes[14:16], "big")
        s = str.format(f"{i:04}")
        rstr += str.format(f'Input3="{s[:2]}.{s[2:]}" ')
        return rstr + str.format(f'RawBytes="{pretty_hex_bytes(data_bytes)}"')
    else:
        return pretty_hex_bytes(data_bytes)


__all__ = ["Easygen3500XT"]
