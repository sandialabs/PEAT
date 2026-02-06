"""
Core functionality for interrogating SEL relays.

Supported relay models (not an exhaustive list)

- 300G (Generator Relay)
- 311C (Transmission Protection System)
- 311L (Line Current Differential Protection and Automation System)
- 351 (Protection System)
- 351S (Protection Relay)
- 387 (Current Differential and Overcurrent Relay)
- 411L (Advanced Line Differential Protection, Automation, and Control System)
- 451 (Protection Automation Control)
- 487E (Transformer Protection Relay)
- 587Z (High-Impedance Differential Relay)
- 700G (Generator Protection Relay)
- 710 (Motor Protection Relay)
- 751 (Feeder Protection Relay)
- 2032 (Communications Processor)
- 2411 (Programmable Automation Controller)

.. note::
   700G FTP server port check will cause errno 11,
   "Resource temporarily unavailable". We fix this
   by resetting the connection after an ack, which
   is exactly what nmap does. While it's not as "kind",
   it's probably less likely to trigger an issue than
   hitting a device's application code and exiting in
   a non-standard way for the protocol.

.. note::
   PEAT is explicitly NOT checking FTP during identify.

   - The common case is that relays are configured with Telnet+other things
     It is highly unusual for a relay to have FTP enabled but not Telnet.
   - FTP requires login
     - Many other device types listen on FTP (network load)
     - login bans after 3-5 attempts by default
     - we're essentially brute forcing the device
   - FTP login triggers a software alarm

.. note::
   On most relays the FTP password is set by default to
   the Level 2 password. If the L2 password changes, so
   does the FTP password, unless configured otherwise.

.. warning::
   Software alarms will trigger the alarm contact on the relay! Software alarms
   are generated when elevating to level 2 in Telnet/Serial ("2ac"), logging
   into FTP, and possibly elevating to 2ac in the web interface (untested).

Listening network services (services available vary by device)

- FTP (TCP 21) (Not enabled by default)
- Telnet (TCP 23) (usually relays)
- HTTP (TCP 80) (some devices)
- HTTPS (TCP 443) (switches, some other devices)
- SNMP (UDP 161) (switches, some other devices)

Known Tested FIDs.
Not exhaustive, PEAT has been run on many others not documented here.
Also, not all functionality is working or has been tested for these FIDs.
Some may be parsing only, others may only be scan, etc.

- SEL-311C-2-R508-V0-Z104101-D20150219
- SEL-311L-7-R502-V0-Z106006-D20141106
- SEL-351-5-R510-V0-Z103103-D20110429
- SEL-351S-7-R516-V2-Z106105-D20190111
- SEL-411L-1-R124-V0-Z015003-D20190130
- SEL-451-5-R322-V0-Z025013-D20180630
- SEL-487E-3-R317-V1-Z110102-D20190211
- SEL-700G-R200-V0-Z006003-D20180629
- SEL-710-R411-V0-Z007004-D20170623
- SEL-751-R201-V1-Z007003-D20180921
- SEL-751-R300-V3-Z008004-D20210104
- SEL-2032-R115-V1-Z003001-D20151028

Authors

- Christopher Abate
- Christopher Goes
- George Thompson
- Jordan Henry
- Rachel Glockenmeier
- Taegan Williams
"""

import functools
import time
import timeit
from copy import deepcopy
from pathlib import Path
from pprint import pformat
from typing import Literal

import olefile
import serial

from peat import (
    CommError,
    DeviceData,
    DeviceError,
    DeviceModule,
    Interface,
    IPMethod,
    SerialMethod,
    Service,
    consts,
    datastore,
    state,
    utils,
)
from peat.protocols import FTP, check_tcp_port

from .relay_parse import (
    event_data_present,
    parse_and_process_events,
    parse_cfg_txt,
    parse_rdb,
    parse_set_all,
    process_cid_file,
    process_info_into_dev,
)
from .sel_comms import populate_file_listing, pull_files
from .sel_http import SELHTTP
from .sel_serial import SELSerial
from .sel_telnet import SELTelnet

# TODO: auto-construct SET_ALL.TXT from individual files for parse,
#   e.g. a directory of SET_* files.

# TODO: support parse input files:
#   CFG.XML
#   VEC_D.TXT, VEC_E.TXT
#   *.CEV

# TODO: calculate uptime based on time since last "Relay powered up" event
#   AND no power off event.
#   Use: dev.retrieve("event", {...})

# TODO: get BADPASS and other auth events from TAR.TXT
#   Refer to section 7.35 in the SEL351S manual.
#   ACCESS: Asserts while any user is logged in at Access Level B or higher
#   Row SALARM ACCESS ALRMOUT * HALARMA HALARMP HALARML HALARM
#   98 0 0 1 0 0 0 0 0
#   Row * * PASNVAL ACCESSP GRPSW SETCHG CHGPASS BADPASS

# TODO: .CEV file parsing
#   https://github.com/engineerjoe440/pycev
#   https://pycev.readthedocs.io/en/latest/
#       Associate with DNP3/Modbus registers?
#       Create event entries?
#       record.fid => Get FID information
#       record.trigger_time
#       record.frequency
#       record.*_channel_ids (analog, digital, status)
#       record.settings
#       record.group
#       record.*_count

# TODO: improve logic/settings parsing: https://github.com/danyill/sel-settings-terminal/


class SELRelay(DeviceModule):
    """
    Shared functionality for interrogating SEL relays.
    """

    device_type = "Relay"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"
    filename_patterns = [
        "*.rdb",
        "*SET_ALL.TXT",
        "*SET_ALL.txt",
        "*set_all.txt",
        "*CFG.TXT",
        "*CFG.txt",
        "*cfg.txt",
        # SER and CSER
        "*SER.TXT",
        "*SER.txt",
        "*ser.txt",
        # HISTORY and CHISTORY
        "*HISTORY.TXT",
        "*HISTORY.txt",
        "*history.txt",
        # *.CID (e.g. SET_61850.CID)
        "*.CID",
        "*.cid",
    ]

    # These are what's known to work. Others may work as well
    supported_models = [
        "300g",
        "311c",
        "311l",
        "351",
        "351s",
        "387",
        "411l",
        "451",
        "487e",
        "587",
        "587z",
        "700g",
        "710",
        "751",
        "2032",
        "2411",
    ]

    # Add aliases for specific models, e.g. "sel-300g"
    module_aliases = [f"sel-{x}" for x in supported_models]

    # For descriptions of options, refer to examples/peat-config.yaml
    default_options = {
        "ftp": {
            "user": "",
            "pass": "",
            "creds": [
                # NOTE: default lockout is 5 attempts
                ("FTPUSER", "TAIL"),  # 351S, 700G, 710, 751
                ("2AC", "TAIL"),  # 451, 411L, 487E (uses L2 password)
                ("FTP", "TAIL"),  # 351
                # ("ACC", "OTTER"),  # 451, 411L, 487E (uses L1 password)
                # If anonymous access is enabled in settings on some devices
                ("anonymous", "anonymous"),
                ("anonymous", "anonymous@"),
                # ("2ac", "TAIL"),
                # ("FTP", "OTTER"),
                # ("BAC", "OTTER"),
                # ("acc", "OTTER"),
                # ("bac", "OTTER"),
            ],
            "pull_delay": 0.5,
        },
        "web": {
            "user": "",
            "pass": "",
        },
        "sel": {
            "pull_methods": [
                "http",
                "ftp",
                "telnet",
            ],
            "attempt_more_commands": False,
            "allow_telnet_file_download": True,
            "force_telnet_file_download": False,
            "force_serial_pull": False,
            "force_ymodem": False,
            "only_download_files": [],  # ["SET_6.TXT"]
            "only_download_dirs": [],  # ["SETTINGS", "EVENTS"]
            "never_download_files": [],  # ["CFG.XML", "SWCFG.ZIP"]
            "never_download_dirs": [],  # ["EVENTS", "HMI"]
            "restart_after_push": False,
            "old_ftp": False,
            "handle_download_errors": True,
            "creds": {
                "acc": "OTTER",
                # bac: "BREAKER" access level (present on 351S and others)
                "bac": "EDITH",
                "2ac": "TAIL",
                # SEL-451 'cal' default: "Sel-1"
                #   "Sel-1" also seen on: SEL-451-5-R324-V1-Z027013-D20201009
                "cal": "CLARKE",
            },
        },
    }

    # 57600 used by ymodem and by 351 by default
    sel_fallback_baudrates = [9600, 57600, 19200]

    @classmethod
    def _verify_serial(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL Relay via commands sent over a serial connection.
        """
        baudrates = dev.options["baudrates"]  # type: list[int]
        if not baudrates:
            baudrates = cls.sel_fallback_baudrates

        # If baudrate is specified in config, then use it and don't enumerate all baudrates
        if dev.options["serial"]["baudrate"]:
            baudrates = [dev.options["serial"]["baudrate"]]

        timeout = dev.options["serial"]["timeout"]  # type: float

        cls.log.debug(f"Verifying Serial for {dev.serial_port} (timeout: {timeout})")

        for baudrate in baudrates:
            try:
                # TODO: don't use with statement, rely on atexit for cleanup on exit
                with SELSerial(
                    serial_port=dev.serial_port,
                    baudrate=baudrate,
                    timeout=timeout,
                ) as ser:
                    if not ser.test_connection():
                        cls.log.debug(
                            f"Serial connection test failed on "
                            f"{dev.serial_port} with baud {baudrate}"
                        )
                        continue

                    # Mark serial port as active
                    dev._is_active = True

                    if not cls._selascii_get_id(dev, ser):
                        cls.log.warning(f"Baudrate {baudrate} didn't work for {dev.serial_port}")
                        continue

                    iface = Interface(
                        type="rs_232",
                        serial_port=dev.serial_port,
                        baudrate=baudrate,
                        parity="none",
                        stop_bits=1,
                        flow_control="none",
                    )

                    dev.store("interface", iface, lookup="serial_port")

                    if not dev.options["serial"]["baudrate"]:
                        if not dev._runtime_options.get("serial"):
                            dev._runtime_options["serial"] = {}
                        dev._runtime_options["serial"]["baudrate"] = baudrate

                    if not cls._selascii_verify_post_process(dev, ser):
                        return False

                    if not dev.id:
                        dev.id = dev.serial_port

                    return True
            except serial.SerialException as ex:
                # This is needed on Windows to handle several cases
                raise ex
            except Exception as ex:
                cls.log.warning(
                    f"Failed verify of serial port {dev.serial_port} at baudrate {baudrate}: {ex}"
                )
                continue

        return False

    @classmethod
    def _verify_telnet(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL Relay via Telnet commands.
        """
        port = dev.options["telnet"]["port"]  # type: int
        timeout = dev.options["telnet"]["timeout"]  # type: float

        cls.log.debug(f"Verifying Telnet for {dev.ip}:{port} (timeout: {timeout})")

        try:
            with SELTelnet(dev.ip, port, timeout) as tn:
                if not cls._selascii_get_id(dev, tn):
                    return False

                if not cls._selascii_verify_post_process(dev, tn):
                    return False

                return True
        except Exception as ex:
            cls.log.trace(f"Telnet verify failed for {dev.ip} due to exception: {ex}")

        return False

    @classmethod
    def _selascii_get_id(cls, dev: DeviceData, comm: SELTelnet | SELSerial) -> bool:
        id_info = comm.get_id()

        if not id_info:
            cls.log.debug(f"{comm.type} verify failed for {comm.address}: no 'id' data")
            return False

        fid = id_info.get("FID")
        if not fid:
            cls.log.debug(
                f"{comm.type} verify failed for {comm.address}: "
                f"no FID in 'id' command output"
                f"\nRaw output: {id_info}"
            )
            return False

        # Process info from the "id" command, including the FID
        process_info_into_dev(id_info, dev)

        return True

    @classmethod
    def _selascii_verify_post_process(cls, dev: DeviceData, comm: SELTelnet | SELSerial) -> bool:
        # Close the connection cleanly
        try:
            comm.disconnect()
        except Exception as ex:
            cls.log.warning(f"Unclean disconnect during {comm.type} verify: {ex}")

        # Attempt to get RID, TID, and current time from
        # data the relay dumps when "quit" command is run
        # TODO: output is sometimes shown on login (also after certain commands)
        #   Make a generic parser
        #   Check if in output after login (do a read())
        #   Check if in output after exit
        exit_info = {}
        if "exit" in comm.all_output[-1] or "quit" in comm.all_output[-1]:
            try:
                exit_info.update(comm.parse_exit_info(comm.all_output[-1]))
            except Exception as ex:
                cls.log.error(f"Failed to parse {comm.type} exit info: {ex}")

        if exit_info:
            # list so it gets appended if multiple exits occur
            dev.write_file([exit_info], "raw-exit-info.json", merge_existing=True)

            # Set device name to the Relay ID or Terminal ID if present
            if not dev.name:
                for id_candidate in ["RID", "TID"]:
                    if exit_info.get(id_candidate):
                        dev.name = exit_info[id_candidate]
                        break

            process_info_into_dev(exit_info, dev)

        if not dev.name and dev.extra.get("iedName"):
            dev.name = dev.extra["iedName"]

        if dev.description.model:
            cls._check_model(dev.description.model, dev.ip)

        cls.log.info(
            f"Verified {comm.type} for {comm.address}!"
            f"\nModel: {dev.description.model}"
            f"\nName:  {dev.name}"
            f"\nFID:   {dev.firmware.id}"
        )

        return True

    @classmethod
    def _verify_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Verify a device is a SEL Relay via the HTTP web interface.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.debug(
            f"Verifying Relay HTTP for {dev.ip}:{port} using {protocol} (timeout: {timeout})"
        )

        session = SELHTTP(dev.ip, port, timeout)
        logged_in = False

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            logged_in = session.login(
                dev._cache["verified_web_user"],
                dev._cache["verified_web_pass"],
                protocol,
            )
        else:
            if dev.options["web"]["user"] and dev.options["web"]["pass"]:
                creds = {dev.options["web"]["user"]: dev.options["web"]["pass"]}
            else:
                creds = dev.options["sel"]["creds"]

            for username, password in creds.items():
                cls.log.debug(
                    f"Attempting SEL Relay HTTP login to {dev.ip} with user '{username}'"
                )

                logged_in = session.login(username, password, protocol)

                if logged_in:
                    dev._cache["verified_web_user"] = username
                    dev._cache["verified_web_pass"] = password
                    dev.related.user.add(username)
                    break

        if logged_in:
            # Pull info about device including the model number
            if not session.get_device_features(dev):
                cls.log.warning(
                    f"Failed to pull additional HTTP info from "
                    f"{dev.ip}:{port} after successful login"
                )

            if dev.description.model:
                cls._check_model(dev.description.model, dev.ip)

            # Cache the session using this protocol
            if not dev._cache.get("web_session"):
                dev._cache["web_session"] = session
                dev._cache["web_protocol"] = protocol
            else:
                session.disconnect()

            cls.log.info(f"HTTP verification successful for {dev.ip}:{port}")
            return True

        session.disconnect()
        cls.log.debug(f"Relay HTTP verification failed for {dev.ip}:{port}")

        return False

    @classmethod
    def _check_model(cls, model: str, dev_id: str) -> bool:
        """
        Emit a warning if the model is not supported by PEAT.
        Return false if not supported, return true if it is.
        """
        if model.lower() not in cls.supported_models:
            cls.log.warning(
                f"{dev_id} is a SEL device, however the model '{model}' is not "
                f"familiar to PEAT and has not been tested, so your mileage "
                f"may vary. Please report this signature to the PEAT team! "
                f"(peat@sandia.gov)"
            )
            return False
        return True

    @classmethod
    def pull_configs(cls, dev: DeviceData, comms: FTP | SELTelnet | SELSerial) -> bool:
        all_files = pull_files(dev, comms)

        if not all_files:
            return False

        successful = True

        # Parse Sequential Event Recorder (SER) events
        events = []
        if all_files.get("SER.TXT") and all_files["SER.TXT"]["data"].strip():
            events = parse_and_process_events(all_files["SER.TXT"]["data"], "SER.TXT", dev)[0]

        # Fallback to parsing CSER if SER parsing fails
        if not events and all_files.get("CSER.TXT") and all_files["CSER.TXT"]["data"].strip():
            parse_and_process_events(all_files["CSER.TXT"]["data"], "CSER.TXT", dev)

        # Parse CFG.TXT, if it's present
        if (
            all_files.get("CFG.TXT")
            and all_files["CFG.TXT"]["data"].strip()
            and all_files["CFG.TXT"]["data"].strip() != "=>"
        ):
            try:
                parse_cfg_txt(all_files["CFG.TXT"]["data"], dev)
            except Exception as ex:
                cls.log.warning(f"Failed to parse CFG.TXT pulled from {dev.address}: {ex}")
                successful = False

        if all_files.get("SET_ALL.TXT") and all_files["SET_ALL.TXT"]["data"].strip():
            set_all = all_files["SET_ALL.TXT"]

            # Path on the device (PurePosixPath)
            dev.logic.file.path = set_all["device_path"]

            # Path locally where PEAT is running (Path)
            if set_all["local_path"]:
                dev.logic.file.local_path = set_all["local_path"]

            # Populate the "file" fields with the downloaded file
            dev.populate_fields()

            parse_res = cls.parse_config(set_all["data"], dev)
            if not parse_res:
                cls.log.error(f"Failed to parse SET_ALL.TXT pulled from {dev.address}")
                successful = False

            cls.update_dev(dev)  # Populate any fields that are unset
        else:
            cls.log.warning(
                f"SET_ALL.TXT was not pulled from {dev.address} and so logic "
                f"parsing was skipped. The file may not exist on this device model."
            )

        for filename, file_info in all_files.items():
            if filename.upper().endswith(".CID") and file_info["data"]:
                process_cid_file(
                    data=file_info["data"], filepath=file_info["device_path"], dev=dev
                )

        return successful

    @classmethod
    def pull_more_commands(cls, dev: DeviceData, comms: SELTelnet | SELSerial) -> bool:
        """
        Attempt to get more info via terminal commands
        (get_sta, show_eth, show_status, etc.).

        If any of the commands are successful, this returns true.
        """

        comms.model = dev.description.model  # leak some hints
        comms.elevate(1, dev.options["sel"]["creds"])

        # NOTE: the SEL-2032 is no longer supported by SEL,
        # so how PEAT accesses it shouldn't need to change.
        if dev.description.model == "2032":
            comms.POST_WRITE_SLEEP = 4.0
            commands = {
                "ser": comms.show_ser,  # list[str] (parse with parsing funcs)
                "sta": comms.get_sta,  # dict[str, Union[datetime, str]], with FID and other info
                "dnpmap": functools.partial(comms.exec_read, "dnpmap", added_delay=2.0),
                # "modmap": functools.partial(comms.exec_read, "modmap", added_delay=2.0),
                "who": functools.partial(comms.exec_read, "who", added_delay=3.0),
                "status": functools.partial(comms.exec_read, "status", added_delay=4.0),
                "card_17": functools.partial(comms.exec_read, "card 17", added_delay=4.0),
                "card_18": functools.partial(comms.exec_read, "card 18", added_delay=4.0),
            }
        else:
            commands = {
                # History commands first
                # TODO: ser has timeout issues on large SER logs
                "ser": comms.show_ser,  # list[str] (parse with parsing funcs)
                "his": comms.show_his,  # list[str] (parse with parsing funcs)
                "sta": comms.get_sta,  # dict[str, Union[datetime, str]], with FID and other info
                "device_time": comms.get_device_time,  # datetime
                "active_group": comms.get_active_group,
                # TODO: fix parsing code in SELAscii.show_mac()
                "mac": comms.show_mac,  # dict[str, str]
                "eth": comms.show_eth,  # list[str]  (this is pretty raw)
                "bre": comms.show_bre,  # list[str]
                "eve": comms.show_eve,  # list[str]
                "sum": comms.show_sum,  # list[str]
                "status": comms.show_status,  # list[str]
            }

            # required by most models for SER and HIS
            # if elevation fails, continue anyway
            comms.elevate(2, dev.options["sel"]["creds"])

        cls.log.info(f"Attempting to run {len(commands)} SEL terminal commands on {dev.address}")

        results = {}
        for cmd, func in commands.items():
            try:
                raw_res = func()
                if raw_res:
                    # save timestamp of when each command was run
                    results[cmd] = {
                        "cmd": cmd,
                        "func": repr(func),
                        "timestamp": utils.utc_now(),
                        "result": raw_res,
                    }
                else:
                    cls.log.warning(f"No output from '{cmd}' function on {dev.address}")
            except Exception as ex:
                cls.log.warning(f"Failed to run function '{cmd}' on {dev.address}: {ex}")

        if not results:
            cls.log.error(f"No commands were successful on {dev.address}")
            return False
        else:
            cls.log.info(
                f"{len(results)} commands successful on {dev.address} "
                f"(total attempted: {len(commands)})"
            )

        # Dump all of the commands to disk for debugging or investigation
        dev.write_file(results, "additional-command-outputs.json")

        # Parse the results
        try:
            if results.get("sta"):
                process_info_into_dev(results.pop("sta")["result"], dev=dev)

            if results.get("device_time"):
                dev.extra["device_time"] = results.pop("device_time")["result"]

            if results.get("ser"):
                ser_data = "\n".join(results.pop("ser")["result"])
                parse_and_process_events(ser_data, dataset="SER", dev=dev)

            if results.get("his"):
                his_data = "\n".join(results.pop("his")["result"])
                parse_and_process_events(his_data, dataset="HIS", dev=dev)

            if results.get("mac"):
                for mac_name, mac_value in results.pop("mac")["result"].items():
                    dev.related.mac.add(mac_value)
                    dev.extra[mac_name] = mac_value

            if results.get("active_group"):
                active_group = results.pop("active_group")["result"]
                dev.extra["active_settings_group"] = active_group

            # if results.get("eth"):
            #     pass  # TODO
            # if results.get("bre"):
            #     pass  # TODO
            # if results.get("eve"):
            #     pass  # TODO
            # if results.get("sum"):
            #     pass  # TODO
            # if results.get("status"):
            #     pass  # TODO
        except Exception:
            cls.log.exception(f"Unexpected error processing command results from {dev.address}")
            dev.extra["additional_command_outputs"] = results
            return False

        # Only add to Extra what wasn't parsed or used
        if results:
            dev.extra["additional_command_outputs"] = results

        return True

    @classmethod
    def pull_telnet(cls, dev: DeviceData, pull_files: bool = True) -> bool:
        """
        Pull and parse configuration file(s) from the relay via Telnet.
        """
        with SELTelnet(
            ip=dev.ip,
            port=dev.options["telnet"]["port"],
            timeout=dev.options["telnet"]["timeout"],
        ) as tn:
            if not tn.test_connection():
                cls.log.error(f"Failed Telnet pull from {dev.ip}: failed to connect")
                return False

            if not tn.elevate(1, dev.options["sel"]["creds"]):
                cls.log.error(f"Failed Telnet pull from {dev.ip}: login failed")
                return False

            dev.related.user.update(tn.successful_usernames)
            successful = True

            # Get more info via terminal commands (get_sta, show_eth, show_status, etc.)
            if dev.options["sel"]["attempt_more_commands"]:
                # At least one command should succeed
                if not cls.pull_more_commands(dev=dev, comms=tn):
                    cls.log.error("Failed to pull more Telnet commands")
                    successful = False

            if pull_files:
                if not cls.pull_configs(dev, tn):
                    cls.log.warning(f"There were issues downloading files via Telnet for {dev.ip}")
                    successful = False
            else:
                cls.log.debug(f"Skipping file pull via Telnet for {dev.ip}")

            return successful

    @classmethod
    def pull_serial(cls, dev: DeviceData) -> bool:
        """
        Pull and parse configuration file(s) from the relay via serial.
        """
        # TODO: cache the serial object between verify and pull,
        #   to avoid closing and reopening connection for no reason
        if not dev.options["serial"]["baudrate"]:
            if not cls._verify_serial(dev):
                cls.log.error(
                    f"Failed pull from {dev.serial_port}: _verify_serial() failed "
                    f"(verify was run because no baudrate was specified for the "
                    f"device in the PEAT YAML configuration file)"
                )
                return False

        with SELSerial(
            serial_port=dev.serial_port,
            baudrate=dev.options["serial"]["baudrate"],
            timeout=dev.options["timeout"],
            force_ymodem=dev.options["sel"]["force_ymodem"],
        ) as ser:
            if not ser.test_connection():
                cls.log.error(f"Failed pull from {dev.serial_port}: connection failed")
                return False

            if not ser.elevate(1, dev.options["sel"]["creds"]):
                cls.log.error(f"Failed pull from {dev.serial_port}: login failed")
                return False

            dev.related.user.update(ser.successful_usernames)

            if dev.options["sel"]["force_ymodem"]:
                # YMODEM only works on Linux or OSX (or any system with rz/sz commands)
                if consts.WINDOWS:
                    raise DeviceError(
                        f"YMODEM pulls do not work on Windows "
                        f"(sel.force_ymodem was configured for {dev.serial_port})"
                    )
                cls.log.warning(f"Forcing use of YMODEM for serial pull from {dev.serial_port}")

            successful = True

            if not cls.pull_configs(dev, ser):
                cls.log.warning(
                    f"There were issues downloading files via Serial for {dev.serial_port}"
                )
                successful = False

            # Get more info via terminal commands (get_sta, show_eth, show_status, etc.)
            if dev.options["sel"]["attempt_more_commands"]:
                # At least one command should succeed
                if not cls.pull_more_commands(dev=dev, comms=ser):
                    cls.log.error("Failed to pull more serial commands")
                    successful = False

            return successful

    @classmethod
    def pull_ftp(cls, dev: DeviceData) -> bool:
        """
        Pull and parse configuration file(s) from the relay via FTP.
        """
        if not cls._setup_ftp(dev):
            cls.log.error(f"FTP pull failed for {dev.ip}: failed setup")
            return False

        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                if not ftp.login(username, dev.options["ftp"]["pass"]):
                    cls.log.error(
                        f"Failed to pull config from {dev.ip}: FTP login "
                        f"failed (user: '{username}')"
                    )
                    return False

                dev.related.user.add(username)

                delay = dev.options["ftp"]["pull_delay"]
                cls.log.info(
                    f"FTP logged in to {dev.ip} as '{username}', sleeping for "
                    f"{delay} seconds before running 'getwelcome()'..."
                )
                time.sleep(delay)

                if not ftp.getwelcome():
                    cls.log.error(
                        f"Failed to pull FTP from {dev.ip}: "
                        f"'getwelcome' failed after login succeeded"
                    )
                    return False

                # Download files
                if not cls.pull_configs(dev, ftp):
                    cls.log.error(f"Failed to pull FTP from {dev.ip}: no files were downloaded")
                    return False

                return True
        except CommError as ex:
            cls.log.warning(f"Failed FTP pull from {dev.ip}: connection failed")
            cls.log.trace(f"Exception: {ex}")
        except Exception as ex:
            cls.log.warning(f"Failed FTP pull from {dev.ip} due to an unhandled exception: {ex}")

        return False

    @classmethod
    def pull_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Pull configuration and other data from the relay via HTTP.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.info(f"Pulling data via HTTP from {dev.ip}:{port} (timeout: {timeout})")

        if not dev._cache.get("web_session"):
            cls.log.debug(
                f"No web session cached in pull_http() for "
                f"{dev.ip}:{port}, creating new session..."
            )
            dev._cache["web_session"] = SELHTTP(dev.ip, port, timeout)
            dev._cache["web_protocol"] = protocol
        else:
            cls.log.debug(f"Using existing web session for {dev.ip}:{port}")

        session = dev._cache["web_session"]

        if not session.relay_logged_in:
            cls.log.debug(f"Session not logged in, logging in to {dev.ip}:{port}")

            username = dev._cache.get("verified_web_user")
            if not username:
                username = dev.options["web"]["user"]
            if not username:
                username = "ACC"

            password = dev._cache.get("verified_web_pass")
            if not password:
                password = dev.options["web"]["pass"]
            if not password:
                password = "OTTER"

            if not session.login(username, password, protocol):
                cls.log.error(
                    f"Failed to login to web interface on {dev.ip}:{port} with user '{username}'"
                )

                session.disconnect()
                if dev._cache.get("web_session"):
                    del dev._cache["web_session"]
                if dev._cache.get("web_protocol"):
                    del dev._cache["web_protocol"]

                return False

            dev.related.user.add(username)
            dev._cache["verified_web_user"] = username
            dev._cache["verified_web_pass"] = password

        web_methods = [
            session.get_status,
            session.get_communications,
            session.get_port_settings,
            session.get_front_panel_settings,
            session.get_sequential_events,
            session.get_historical_events,
            session.get_meter_automation,
            session.get_meter_protection,
            session.get_meter_energy,
            session.get_output_data,
        ]

        # This gets called during verify, no reason to call it again.
        # However, if it HASN'T been called yet, then it needs to be
        # called BEFORE the other methods. Thus, insert(0).
        if not dev._is_verified:
            web_methods.insert(0, session.get_device_features)

        cls.log.info(
            f"Beginning web pull from {dev.ip}:{port} using {len(web_methods)} web methods"
        )

        # Note the number of successful methods somewhere
        dev._cache["num_successful_methods"] = 0
        was_successful = True

        for method in web_methods:
            time.sleep(0.2)  # attempt to avoid overloading web server

            cls.log.info(f"Running '{method.__name__}' for {dev.ip}:{port}")
            try:
                method_result = method(dev)  # type: bool

                if not method_result:
                    cls.log.warning(
                        f"No data from HTTP method '{method.__name__}' on {dev.ip}:{port}"
                    )
                else:
                    dev._cache["num_successful_methods"] += 1
            except Exception:
                cls.log.exception(f"'{method.__name__}' failed on {dev.ip}:{port}")
                was_successful = False
                continue

        cls.log.info(
            f"Finished pulling data via web interface from {dev.ip}:{port} "
            f"({dev._cache['num_successful_methods']} methods were "
            f"successful out of {len(web_methods)} methods attempted)"
        )

        return was_successful

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """
        Pull and parse all configuration files and data from the SEL relay.
        """

        # If the user hasn't specified a protocol to use, there's a
        # serial port configured for the host, and the type of operation
        # is serial, then do a serial pull.
        if dev.options["sel"]["force_serial_pull"] or (
            dev.serial_port and state.comm_type == "serial"
        ):
            return cls.pull_serial(dev)

        if not dev.options["sel"]["pull_methods"]:
            cls.log.error(f"The 'sel.pull_methods' option is empty or null for {dev.ip}")
            return False

        for method in dev.options["sel"]["pull_methods"]:
            if method not in cls.default_options["sel"]["pull_methods"]:
                cls.log.error(
                    f"Invalid 'sel.pull_methods' method '{method}' for {dev.ip}, it must "
                    f"be one of {cls.default_options['sel']['pull_methods']}"
                )
                return False

        pull_results = {}  # type: dict[str, bool]
        files_pulled = False
        for method in dev.options["sel"]["pull_methods"]:
            if dev.service_status({"protocol": method}) == "closed":
                cls.log.warning(f"Failed to pull {method} on {dev.ip}: {method} port is closed")
                continue

            # TODO: handle case where dev._is_verified is False,
            # e.g. if pull() is called directly without a scan.

            if method == "telnet":
                pull_files = False

                if (
                    not files_pulled and dev.options["sel"]["allow_telnet_file_download"]
                ) or dev.options["sel"]["force_telnet_file_download"]:
                    pull_files = True

                pull_results[method] = cls.pull_telnet(dev, pull_files=pull_files)

                if pull_results[method] and pull_files:
                    files_pulled = True

            elif method == "ftp":
                pull_results[method] = cls.pull_ftp(dev)

                if pull_results[method]:
                    files_pulled = True

            else:
                web_protocol = None
                if dev._cache.get("web_protocol"):
                    web_protocol = dev._cache["web_protocol"]
                else:
                    for proto in ["http", "https"]:
                        s = dev.retrieve("service", {"protocol": proto})
                        if s and (s.enabled or s.status == "open"):
                            web_protocol = proto

                if web_protocol:
                    if not dev._cache.get("web_protocol"):
                        dev._cache["web_protocol"] = web_protocol
                    try:
                        # pull using the open protocol (http or https)
                        pull_results[method] = cls.pull_http(dev, web_protocol)
                    except Exception:
                        cls.log.exception(
                            f"Web pull via '{web_protocol}' of {dev.ip} "
                            f"failed due to unhandled exception"
                        )
                        pull_results[method] = False
                else:
                    cls.log.warning(
                        f"Failed to determine HTTP/HTTPS protocol for {dev.ip},"
                        f"falling back to plain 'http'."
                    )
                    pull_results[method] = cls.pull_http(dev, "http")

            if not pull_results[method]:
                cls.log.warning(f"{method} pull failed for {dev.ip}")
            else:
                cls.log.debug(f"{method} pull successful for {dev.ip}")

        return all(m for m in pull_results.values())

    @classmethod
    def _push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Reconfigure the SEL device by writing config files.

        .. warning::
           Modifying the port configuration (SET_P*) will kill any connections
           to that port. This can affect the port PEAT is using to push configs!

        .. note::
           Filenames must be capitalized, e.g. SET_ALL.TXT or SET_1.TXT

        Args:
            dev: Device to push to
            to_push: Path to relay configuration files to upload (SET_*.TXT)
            push_type: this should be 'config'

        Returns:
            If the push was successful
        """
        if push_type != "config":
            cls.log.critical(f"Unsupported push type {push_type}, expected 'config'")
            return False

        if not isinstance(to_push, Path):
            cls.log.error(
                f"Expected path for push, got type '{type(to_push)}'. "
                f"Ensure you specify a path to a config file or directory "
                f"with configs to upload, not raw data."
            )
            return False

        # Ensure we can connect via FTP
        # TODO: before pushing, read FTP user out of config
        #   just do: dev.lookup("service", {"protocol": "ftp"}).user
        if not cls._setup_ftp(dev):
            cls.log.error(f"FTP push failed for {dev.ip}: failed setup")
            return False

        # TODO: Ability to push using a SET_ALL to reconstruct files, e.g.
        #   peat push -d selrelay -i 192.0.2.123 -- SET_ALL.TXT
        # NOTE: I don't think we can push the actual SET_ALL.TXT,
        #   may return a permission denied error.

        # TODO: support pushing multiple configs at once, e.g.
        #   peat push -d selrelay -i 192.0.2.123 -- SET_1.TXT SET_6.TXT
        #   This will require modifying the push API and CLI args a bit
        #   to support multiple filenames as arguments.

        # TODO: rebuild connection on failures, e.g. timeout mid-push
        # TODO: if SET_P* file(s) have a different IP, they need to be
        #   done last, otherwise the subsequent configs will fail.
        #   sort config update order so SET_P* files are last, with
        #   ethernet ports at the end.
        # TODO: if SET_P in config name, then prepare ftp connection
        #  to reconnect/rebuild, and update the IP used to connect
        #  if it was changed. set a internal PEAT flag indicating
        #  a IP change occurred during the same run.
        # TODO: option to pull current configs and only push those whose hash changed

        # peat push -d selrelay -i 192.0.2.123 -- SET_1.TXT
        cls.log.info(f"Reading config(s) from {to_push}")

        if to_push.is_dir():
            config_files = sorted(to_push.glob("SET_*.TXT"))
            if "SET_ALL.TXT" in (x.name for x in config_files):
                cls.log.warning(f"Ignoring SET_ALL.TXT in config files for push to {dev.ip}.")
                config_files = [x for x in config_files if x.name != "SET_ALL.TXT"]
            if not config_files:
                cls.log.error(f"Push failed: couldn't find any configs in {to_push.as_posix()}")
                return False
            cls.log.debug(f"Using {len(config_files)} config files from dir {to_push}")
        elif to_push.is_file():
            # TODO: support pushing *.rdb files (just extract the set_all), e.g.
            #   peat push -d selrelay -i 192.0.2.123 -- sel_351.rdb
            # We'll need to implement splitting SET_ALL into separate config files
            # before implementing this.
            config_files = [to_push]
            cls.log.debug(f"Push: using config file {to_push.as_posix()}")
        else:
            cls.log.critical(f"Invalid file for push to {dev.ip}: {to_push}")
            return False

        cls.log.trace(f"config_files: {config_files}")

        try:
            with FTP(dev.ip, dev.options["ftp"]["port"], 120.0) as relay:
                if not relay.login(
                    user=dev.options["ftp"]["user"], passwd=dev.options["ftp"]["pass"]
                ):
                    cls.log.error(f"Failed to push config to {dev.ip}: FTP login failed")
                    return False

                delay = dev.options["ftp"]["pull_delay"]
                cls.log.debug(
                    f"FTP logged in to {dev.ip}, sleeping for {delay} "
                    f"seconds before running getwelcome()..."
                )
                time.sleep(delay)
                if not relay.getwelcome():
                    cls.log.error(
                        f"Failed to push config to {dev.ip}: "
                        f"getwelcome failed after login succeeded"
                    )
                    return False

                cls.log.debug(
                    f"Sleeping for {delay} seconds before pushing configs to {dev.ip}..."
                )
                time.sleep(delay)

                # Find where the configs are
                # According to the documentation, all 700-series relays
                # put their configs in the root directory. However, this
                # is not always the case, as we've seen a directory structure
                # on a 700G with the fancy front panel display.
                if not dev.extra.get("file_listing") or not dev.extra.get(
                    "settings_root_directory"
                ):
                    populate_file_listing(dev, relay)

                # Push only the files on the relay already and in
                # the order the relay displays them
                settings_root = dev.extra["settings_root_directory"]
                on_relay = [x.upper() for x in dev.extra["file_listing"][settings_root]]

                # Compare local file names with those on the device
                local_names = [x.name for x in config_files]
                local_not_on_relay = [x for x in local_names if x not in on_relay]
                if local_not_on_relay:
                    cls.log.warning(
                        f"{len(local_not_on_relay)} files being pushed are not "
                        f"currently present on the relay (they're new files). "
                        f"Ensure you are pushing the right files to the "
                        f"appropriate device! List of files: "
                        f"{local_not_on_relay}"
                    )

                on_relay_not_local = [x for x in on_relay if x not in local_names]
                if on_relay_not_local:
                    cls.log.debug(
                        f"{len(on_relay_not_local)} files exist on the relay, "
                        f"but are not present in the configs being pushed. This "
                        f"is expected if you're pushing a subset of configs "
                        f"(e.g. just SET_1.TXT). List of files: "
                        f"{on_relay_not_local}"
                    )

                # If the settings are in a "SETTINGS" directory, then change
                # directories before transferring configs ("cd SETTINGS")
                if settings_root == "SETTINGS":
                    cls.log.info("Changing directory to 'SETTINGS' before pushing configs")
                    relay.cd("/SETTINGS")

                file_delay = 2
                cls.log.info(
                    f"Preparing to transfer {len(config_files)} config "
                    f"files to {dev.ip}. This will take at least "
                    f"{file_delay * (len(config_files) + 1)} seconds."
                )
                transfer_start = timeit.default_timer()

                # Transfer all configs except communication port configs
                for conf_file in config_files:
                    if "SET_P" not in conf_file.name:
                        cls.log.info(
                            f"Transferring config '{conf_file.name}' ({conf_file.as_posix()})"
                        )
                        with conf_file.open("rb") as f:
                            relay.upload_text(conf_file.name, f)
                        cls.log.info(f"{conf_file.name} config sent")
                        cls.log.debug(f"Sleeping for {file_delay} seconds...")
                        time.sleep(file_delay)

                # Transfer configuration port configs
                for conf_file in config_files:
                    if "SET_P" in conf_file.name:
                        cls.log.info(
                            f"Transferring communication port config "
                            f"'{conf_file.name}' ({conf_file.as_posix()})"
                        )
                        with conf_file.open("rb") as f:
                            relay.upload_text(conf_file.name, f)
                        cls.log.info(f"{conf_file.name} communication port config sent")
                        cls.log.debug(f"Sleeping for {file_delay} seconds...")
                        time.sleep(file_delay)
                transfer_time = timeit.default_timer() - transfer_start
                cls.log.info(
                    f"Completed transfer of {len(config_files)} config "
                    f"files to {dev.ip} in {utils.fmt_duration(transfer_time)}"
                )
                # Prevent disconnection errors from skipping restart
                try:
                    relay.disconnect()
                except Exception:
                    pass

            cls.log.info(f"Completed configuration of relay {dev.ip} via FTP")

            # Reboot the device if 'sel.restart_after_push' is true
            if dev.options["sel"]["restart_after_push"]:
                pre_delay = 5
                cls.log.info(f"Waiting {pre_delay} seconds before restarting {dev.ip}")
                time.sleep(pre_delay)
                return cls.restart_relay_telnet(dev)
            else:
                cls.log.info(
                    "Note: the relay was NOT restarted, as most config changes "
                    "don't require a reboot to take effect. If you need to restart "
                    "the relay, re-run the push with 'sel.restart_after_push' set to true."
                )
                return True
        except CommError as ex:
            cls.log.debug(f"Failed to push config to {dev.ip}: connection failed")
            cls.log.trace(f"Exception: {ex}")
            return False
        except Exception as ex:
            cls.log.warning(
                f"Failed to push config to {dev.ip} due to an unhandled exception: {ex}"
            )
            return False

    @classmethod
    def _setup_ftp(cls, dev: DeviceData) -> bool:
        cls.log.trace2(f"_setup_ftp() for {dev.ip}")

        if dev.options["ftp"].get("user") and dev.options["ftp"].get("pass"):
            return True

        port = dev.options["ftp"]["port"]
        if not dev.retrieve("service", {"port": port}):
            if not check_tcp_port(dev.ip, port, reset=True):
                cls.log.error(f"Failed FTP setup: TCP port {port} is not open on {dev.ip}")
                return False
            else:
                svc = Service(port=port, transport="tcp", status="open")
                dev.store("service", svc, lookup="port")

        # TODO: document this behavior
        #   formally codify this as "default fallback behavior"
        #   based on what we know from manuals and experience
        #   with different models. if creds are known, then
        #   they should be specified in the PEAT config YAML.
        if not dev._runtime_options.get("ftp"):
            dev._runtime_options["ftp"] = deepcopy(cls.default_options["ftp"])
        elif not dev._runtime_options["ftp"].get("creds"):
            dev._runtime_options["ftp"]["creds"] = deepcopy(cls.default_options["ftp"]["creds"])

        # Set informed defaults if login credentials aren't manually specified
        if dev.options["ftp"]["creds"] == cls.default_options["ftp"]["creds"]:
            cls.log.trace(f"FTP creds for {dev.ip} are: INFORMED DEFAULTS")

            if dev.description.model in ["351S", "700G", "710", "751"]:
                utils.move_item(dev._runtime_options["ftp"]["creds"], 0, ("FTPUSER", "TAIL"))
            elif dev.description.model in ["451", "411L", "487E"]:
                utils.move_item(dev._runtime_options["ftp"]["creds"], 0, ("2AC", "TAIL"))
                dev._runtime_options["ftp"]["creds"].insert(1, ("ACC", "OTTER"))
            elif dev.description.model in ["351"]:
                utils.move_item(dev._runtime_options["ftp"]["creds"], 0, ("FTP", "TAIL"))
            elif dev.description.model in ["2032"]:
                utils.move_item(dev._runtime_options["ftp"]["creds"], 0, ("2AC", "TAIL"))
        else:
            cls.log.trace(f"FTP creds for {dev.ip} are: USER PROVIDED")

        timeout = dev.options["ftp"]["timeout"]
        delay = dev.options["ftp"]["pull_delay"]
        attempts = 0

        for creds in dev.options["ftp"]["creds"]:
            attempts += 1
            try:
                with FTP(dev.ip, port, timeout) as relay:
                    if not relay.login(creds[0], creds[1]):
                        cls.log.trace(f"FTP login creds {creds} failed for {dev.ip}")
                        continue

                    cls.log.trace(
                        f"FTP logged in to {dev.ip}, sleeping for {delay} "
                        f"seconds before running getwelcome()..."
                    )

                    time.sleep(delay)

                    if not relay.getwelcome():
                        cls.log.warning(
                            f"FTP setup failed for {dev.ip}: "
                            f"getwelcome failed after login succeeded"
                        )
                        return False

                    cls.log.debug(f"FTP login succeeded on {dev.ip} after {attempts} attempt(s)")

                    dev._runtime_options["ftp"]["user"] = creds[0]
                    dev._runtime_options["ftp"]["pass"] = creds[1]

                    dev.related.user.add(creds[0])

                    ftp_svc = Service(
                        protocol="ftp", port=port, status="verified", transport="tcp"
                    )

                    dev.store("service", ftp_svc, lookup=["protocol", "port"])

                    return True
            except CommError as ex:
                cls.log.debug(f"FTP setup failed for {dev.ip}: connection failed")
                cls.log.trace(f"Exception: {ex}")
                return False
            except Exception as ex:
                cls.log.warning(
                    f"FTP verification failed for {dev.ip} due to an unhandled exception: {ex}"
                )
                return False

        cls.log.debug(
            f"FTP setup failed for {dev.ip}: no credentials were valid ({attempts} attempts)"
        )

        return False

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        # "file" can be one of the following:
        # - a SET_ALL.TXT file
        # - a *.rdb file
        # - CFG.TXT, SER.TXT, CSER.TXT, *.CID, and others
        #
        # Some examples are in peat/tests/modules/sel/data_files/

        raw_data = file.read_bytes()

        # CFG.TXT, SER.TXT, CSER.TXT, HISTORY.TXT, CHISTORY.TXT, *.CID
        f_name = file.name.lower()
        if "cfg" in f_name or "ser" in f_name or "history" in f_name or f_name.endswith(".cid"):
            if not dev:
                dev = datastore.get(f"selrelay_{file.stem.lower()}", "id")

            if f_name.endswith(".cid"):
                cid_extracted = process_cid_file(raw_data, file, dev)

                if not cid_extracted:
                    return None
            elif "ser" in f_name or "history" in f_name:
                if not event_data_present(raw_data):
                    cls.log.warning(f"No event data in {file.name}")
                    return dev

                events, info = parse_and_process_events(raw_data, file.name, dev)

                if not events and not info:
                    return None
            else:
                parse_cfg_txt(raw_data, dev)

            cls.update_dev(dev)  # Populate any fields that are unset

            return dev

        # NOTE: isOleFile will interpret the argument as a filename string
        # if the length of the data is smaller than 1536 bytes. To avoid this,
        # we always pass it a file pointer.
        with file.open("rb") as fp:
            is_rdb = olefile.isOleFile(fp)

        # *.rdb SEL project files use a file structure called
        # Compound File Binary (CFB) Format or Microsoft OLE2 File.
        # isOleFile() checks the file for the magic number at the
        # start of the header to determine if it is the correct format.
        temp_path = None
        if is_rdb:
            cls.log.debug("Input data is in CFB format, parsing as a RDB project")
            to_parse = parse_rdb(raw_data)  # *.rdb

            # Save the extracted SET_ALL data from the rdb to a temporary file
            # This is helpful if debugging an issue with parsing of rdb files
            temp_path = utils.write_temp_file(to_parse, "extracted_SET_ALL.txt")
        else:
            cls.log.debug("Input data is text, parsing as a non-RDB config file")
            to_parse = raw_data.decode("utf-8")  # SET_ALL.TXT

        dev = cls.parse_config(set_all=to_parse, dev=dev)

        if not dev:
            return None

        if is_rdb:
            dev.write_file(raw_data, "raw-rdb-config.rdb")

            if temp_path and temp_path.exists():
                utils.move_file(temp_path, dev.get_out_dir())

        dev.logic.file.local_path = file

        cls.update_dev(dev)  # Populate any fields that are unset

        return dev

    @classmethod
    def parse_config(cls, set_all: str, dev: DeviceData | None = None) -> DeviceData | None:
        try:
            parsed, dev = parse_set_all(set_all_data=set_all, dev=dev)
        except Exception:
            cls.log.exception("Failed config parsing due to a unhandled exception")
            return None

        dev.write_file(parsed, "parsed-config.json")

        if dev.description.model:
            cls._check_model(dev.description.model, dev.description.model)

        # OS information (this is inferred based on fact it's an SEL relay)
        dev.os.family = "rtos"
        dev.os.name = "ThreadX"
        dev.os.vendor.name = "Express Logic"

        # Set the device name if not already set. Key used varies
        # depending on how it's configured and the device model.
        for id_key in ["relay_id", "terminal_id", "station_id"]:
            id_val = parsed.get(id_key)
            if id_val:
                dev.extra[id_key] = id_val  # Store in extra
                if not dev.name:  # Set the name if not set
                    dev.name = parsed[id_key]

        # Only store the logic portions of the config as the "logic"
        logic_keys = ["close_logic", "output_logic", "protection_schemes", "trip_logic"]
        raw_logic = {}
        formatted_logic = {}

        for k in logic_keys:
            if k in parsed:
                raw_logic[k] = parsed[k]
                if k == "protection_schemes":
                    formatted_logic[k] = parsed[k]
                else:
                    formatted_logic[k] = {
                        group: ",".join(f"{k}={v}" for k, v in logic.items())
                        for group, logic in parsed[k].items()
                    }
            else:
                cls.log.warning(f"No logic key {k} in config, not storing in logic...")

        formatted_logic = pformat(formatted_logic)

        # Save the configuration and logic to the data model and a file
        dev.logic.original = set_all
        dev.logic.parsed = formatted_logic

        dev.write_file(raw_logic, "raw-logic.json")
        dev.write_file(formatted_logic, "formatted-logic.txt")
        dev.write_file(set_all, "raw-setall-config.txt")

        return dev

    @classmethod
    def restart_relay_telnet(cls, dev: DeviceData) -> bool:
        """
        Execute a system restart on the SEL relay via Telnet.
        """
        cls.log.info(f"Restarting device {dev.ip} via Telnet...")

        with SELTelnet(
            ip=dev.ip,
            port=dev.options["telnet"]["port"],
            timeout=dev.options["telnet"]["timeout"],
        ) as tn:
            if not tn.elevate(2, dev.options["sel"]["creds"]):
                cls.log.error(f"Failed to restart {dev.ip} via Telnet: login failed")
                return False

            dev.related.user.update(tn.successful_usernames)

            if tn.restart_device():
                cls.log.info(f"Successfully restarted device {dev.ip} via Telnet")
                return True

            cls.log.error(f"Failed to restart device {dev.ip} via Telnet")

            return False


def sel_port_check(dev: DeviceData, protocol: str) -> bool:
    """lambda function set the TCP RST flag for SEL scanning."""
    return check_tcp_port(dev.ip, dev.options[protocol]["port"], reset=True)


SELRelay.ip_methods = [
    # NOTE: We are explicitly NOT port checking FTP. See the note in the
    # docstring at the top of this file.
    IPMethod(
        name="SEL Relay Telnet login",
        description=str(SELRelay._verify_telnet.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRelay._verify_telnet,
        reliability=6,
        protocol="telnet",
        transport="tcp",
        default_port=23,
        port_function=functools.partial(sel_port_check, protocol="telnet"),
    ),
    IPMethod(
        name="SEL Relay HTTP login",
        description=str(SELRelay._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRelay._verify_http, protocol="http"),
        # 1 higher than HTTPS's reliability so we prefer HTTP over HTTPS
        # for older or less robust devices, like the relays.
        reliability=8,
        protocol="http",
        transport="tcp",
        default_port=80,
        port_function=functools.partial(sel_port_check, protocol="http"),
    ),
    # NOTE: the SEL-2730M switch exclusively uses HTTPS and doesn't allow plain HTTP
    IPMethod(
        name="SEL Relay HTTPS login",
        description=str(SELRelay._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRelay._verify_http, protocol="https"),
        reliability=7,
        protocol="https",
        transport="tcp",
        default_port=443,
        port_function=functools.partial(sel_port_check, protocol="https"),
    ),
]


SELRelay.serial_methods = [
    SerialMethod(
        name="SEL Relay serial",
        description=str(SELRelay._verify_serial.__doc__).strip(),
        type="direct",
        identify_function=SELRelay._verify_serial,
        reliability=5,
    )
]


__all__ = ["SELRelay"]
