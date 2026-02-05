"""
PEAT module for Fortinet Fortigate devices.
It has been tested with the Fortigate FG100F firewall.

Types of files that can be parsed:
- Config files (.conf)
- Diagnostic output ("Debug Logs")
- Events from Fortianalyzer
- Memory events

Authors

- Christopher Goes
- Danyelle Loffredo
- Juan Dorantes Cardenas
"""

from pathlib import Path

from scp import SCPClient

from peat import DeviceData, DeviceModule, datastore, exit_handler
from peat.api.identify_methods import IPMethod
from peat.protocols import HTTP, SSH

from .fortigate_conf import fg_conf_to_dict, process_fg_conf
from .fortigate_dbl import parse_fg_debug_log, process_fg_debug_log
from .fortigate_events import parse_fg_events, process_fg_events


class Fortigate(DeviceModule):
    """
    Fortinet Fortigate firewalls.
    This module supports the FG100F firewall.
    """

    device_type = "Firewall"
    vendor_id = "Fortinet"
    vendor_name = "Fortinet, Inc."
    brand = "FortiGate"
    # TODO: file fingerprinting by reading contents of text file
    filename_patterns = [
        "*Fortigate*.conf",
        "*ortigate*.conf",
        "FG100F*.log",
        "fortianalyzer-event*.log",
        "memory-event-*.log",
        "sys_config",
    ]
    can_parse_dir: bool = True
    module_aliases = ["fg100", "fg"]

    default_options = {
        "fortigate": {
            "pull_methods": [
                "ssh",
                "https",
            ],
            "log_pull_timeout": 30.0,
        },
        "ssh": {"user": "", "pass": ""},
        "web": {"user": "", "pass": ""},
    }

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        # Ideally, the user would pass a directory of files. Recurse the tree and parse
        # all the fortigate files there, including log files. Use the .conf file to
        # annotate info such as device name, etc.
        # If a directory is NOT passed, then parse the file piecemeal.

        if dev is None:
            dev = DeviceData()
            datastore.objects.append(dev)

        # parse directory as a whole, conf first, to properly annotate events
        if file.is_dir():
            # Find all the files recursively
            # Parse the config file(s) first
            # then parse the log files
            conf_files = file.rglob("*.conf")
            log_files = file.rglob("*.log")

            for c_path in conf_files:
                cls._fg_parse_file(c_path, dev)

            for l_path in log_files:
                cls._fg_parse_file(l_path, dev)
        # Single File
        else:
            cls._fg_parse_file(file, dev)

        cls.update_dev(dev)
        return dev

    @classmethod
    def _fg_parse_file(cls, path: Path, dev: DeviceData):
        raw_data = path.read_text(encoding="utf-8")

        if path.suffix == ".conf":
            res = fg_conf_to_dict(raw_data)
            process_fg_conf(res, dev)
            dev.write_file(res, f"parsed_config_{path.stem}.json")
        # TODO: peek at file contents to determine if it should be parsed
        elif path.suffix == ".log" and "debug" in path.stem:
            res = parse_fg_debug_log(raw_data)
            process_fg_debug_log(res, dev)
            dev.write_file(res, f"parsed_debug_log_{path.stem}.json")
        # TODO: peek at file contents to determine if it should be parsed
        elif path.suffix == ".log" and "memory-event-" in path.stem:
            res = parse_fg_events(raw_data)
            process_fg_events(res, dev)
            dev.write_file(res, f"parsed_events_{path.stem}.json")
        else:
            cls.log.warning(f"Unknown file type for '{path}'")

        cls.update_dev(dev)

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # Sanity checks in case users messed up config (since there isn't config validation yet)
        if not dev.options["fortigate"]["pull_methods"]:
            cls.log.error(
                f"The 'fortigate.pull_methods' option is empty or null for {dev.ip}"
            )
            return False

        for method in dev.options["fortigate"]["pull_methods"]:
            if method not in cls.default_options["fortigate"]["pull_methods"]:
                cls.log.error(
                    f"Invalid 'fortigate.pull_methods' method '{method}' for {dev.ip}, it must "
                    f"be one of {cls.default_options['fortigate']['pull_methods']}"
                )
                return False

        # Notify user about methods that were skipped
        for method in cls.default_options["fortigate"]["pull_methods"]:
            if method not in dev.options["fortigate"]["pull_methods"]:
                cls.log.debug(
                    f"Skipping {method.upper()} pull from {dev.ip}, "
                    f"'{method}' not in 'fortigate.pull_methods'"
                )

        pull_results = {}

        for method in dev.options["fortigate"]["pull_methods"]:
            if dev.service_status({"protocol": method}) == "closed":
                cls.log.error(
                    f"Failed to pull {method.upper()} on {dev.ip}: {method} port is closed"
                )
                pull_results[method] = False
                continue

            if not dev._is_verified:
                verified = False
                if method == "https" and cls._verify_https(dev):
                    verified = True
                elif method == "ssh" and cls._verify_ssh(dev):
                    verified = True

                if verified:
                    dev._is_verified = True
                else:
                    cls.log.warning(
                        f"Failed to pull {method.upper()} on {dev.ip}: verification failed"
                    )
                    continue

            cls.log.info(f"Pulling data via {method.upper()} from {dev.ip}")
            if method == "https":
                pull_results[method] = cls.pull_https(dev)
            elif method == "ssh":
                pull_results[method] = cls.pull_ssh(dev)

            if not pull_results[method]:
                cls.log.error(f"{method.upper()} pull failed on {dev.ip}")
            else:
                cls.log.debug(f"{method.upper()} pull successful for {dev.ip}")

        return all(bool(result) for result in pull_results.values())

    @classmethod
    def pull_ssh(cls, dev: DeviceData) -> bool:
        """
        Retrieve the sys_config via SCP over SSH from ``/config/sys_config``.

        .. warning::
           SSH pull will only work if ``admin-scp`` option is enabled on the device.
           SSH to device, then run ``config system global``, ``set admin-scp enable``,
           ``end``, and ``exit``.
        """
        try:
            if not dev._cache.get("ssh_session"):
                ssh = SSH(
                    ip=dev.ip,
                    port=dev.options["ssh"]["port"],
                    timeout=dev.options["ssh"]["timeout"],
                    username=dev.options["ssh"]["user"],
                    password=dev.options["ssh"]["pass"],
                )
            else:
                ssh = dev._cache["ssh_session"]

            local_path = dev.get_out_dir() / "sys_config"
            if not local_path.parent.exists():
                local_path.parent.mkdir(exist_ok=True, parents=True)
            remote_path = "/config/sys_config"  # location of config file on machine
            cls.log.info(
                f"Transferring sys_config from '{remote_path}' to '{local_path}'"
            )

            # Download the file
            with SCPClient(ssh.comm.get_transport()) as scp_client:
                scp_client.get(remote_path, str(local_path), preserve_times=True)
                cls.log.info(f"Successfully copied '{remote_path}' to '{local_path}'")

            # TODO: run CLI commands that are run by the debug log, e.g. "get hardware cpu"

            ssh.disconnect()
            exit_handler.unregister(ssh.disconnect, "CONNECTION")

            # parse the result
            cls.log.info(f"Parsing pulled config: {local_path.name}")
            res = fg_conf_to_dict(local_path.read_text(encoding="utf-8"))
            process_fg_conf(res, dev)
            dev.write_file(res, "parsed_sys_config.json")
            return True
        except Exception as ex:
            cls.log.exception(f"SSH pull failed from {dev.ip}: {ex}")
            if "permission denied" in str(ex).lower():
                cls.log.error(
                    "SSH pull likely failed due to SCP not being enabled. "
                    "To enable this, SSH into your device as an administrator, "
                    "run the following commands, then re-run the PEAT pull:"
                    "\n\tconfig system global\n\tset admin-scp enable"
                    "\n\tend\n\texit"
                )
            return False

    @classmethod
    def pull_https(cls, dev: DeviceData) -> bool:
        """
        Pull configuration and other data from the relay via HTTPS.
        """
        if not dev._cache.get("https_session"):
            http = HTTP(
                ip=dev.ip,
                port=dev.options["https"]["port"],
                timeout=dev.options["https"]["timeout"],
                dev=dev,
                protocol="https",
            )
        else:
            http = dev._cache["https_session"]

        cls.log.info(f"Logging in to web interface on {dev.ip}:{http.port}")
        # TODO: use http.url attribute instead of manually creating
        login_resp = http.post(
            url=f"https://{dev.ip}:{http.port}/logincheck",
            dev=dev,
            data={
                "ajax": 1,
                "username": dev.options["web"]["user"],
                "secretkey": dev.options["web"]["pass"],
            },
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
                ),
                "If-Modified-Since": "Sat, 1 Jan 2000 00:00:00 GMT",
            },
        )

        # Expected response.text: '1document.location="/prompt?viewOnly&redir=%2F";'
        if "location" not in login_resp.text or login_resp.status_code != 200:
            cls.log.warning(f"Web login failed to {dev.ip}:{http.port}")
            return False

        pull_timeout = dev.options["fortigate"]["log_pull_timeout"]  # type: float

        # Memory events. This is a ~9+MB file, needs time to download
        cls.log.info(
            f"Downloading all events from 'memory' log location on {dev.ip}, "
            f"this may take up to {pull_timeout} seconds"
        )
        me_resp = http.get("/api/v2/log/memory/event/system/raw", timeout=pull_timeout)
        if not me_resp:
            cls.log.error(
                f"Failed to pull events from 'memory' location on {dev.ip}. "
                f"Try increasing the timeout via the 'fortigate.log_pull_timeout' "
                f"YAML config option, current timeout is set to {pull_timeout}."
            )
            return False

        me_parsed = parse_fg_events(me_resp.text)
        process_fg_events(me_parsed, dev)

        # Move the raw file to results dir, and write parsed config to JSON
        me_files = list(dev.get_sub_dir("http_files").rglob("memory-event-*.log"))
        if me_files:
            me_path = me_files[0]
            me_path.rename(dev.get_out_dir() / me_path.name)
            dev.write_file(me_parsed, f"parsed_events_{me_path.stem}.json")

        # Debug log. This is also a large file, needs time to download, hence timeout
        cls.log.info(
            f"Downloading 'debug' log from {dev.ip}, "
            f"this may take up to {pull_timeout} seconds"
        )
        db_resp = http.get(
            "/api/v2/monitor/system/debug/download", timeout=pull_timeout
        )
        if not db_resp:
            cls.log.error(
                f"Failed to pull debug log from {dev.ip}. "
                f"Try increasing the timeout via the 'fortigate.log_pull_timeout' "
                f"YAML config option, current timeout is set to {pull_timeout}."
            )
            return False

        db_parsed = parse_fg_debug_log(db_resp.text)
        process_fg_debug_log(db_parsed, dev)

        # Move the raw file to results dir, and write parsed config to JSON
        db_files = list(dev.get_sub_dir("http_files").rglob("*_debug.log"))
        if db_files:
            db_path = db_files[0]
            db_path.rename(dev.get_out_dir() / db_path.name)
            dev.write_file(db_parsed, f"parsed_debug_log_{db_path.stem}.json")

        cls.log.info(f"Finished web interface pull from {dev.ip}:{http.port}")
        return True

    @classmethod
    def _verify_ssh(cls, dev: DeviceData) -> bool:
        ssh = SSH(
            ip=dev.ip,
            port=dev.options["ssh"]["port"],
            timeout=dev.options["ssh"]["timeout"],
            username=dev.options["ssh"]["user"],
            password=dev.options["ssh"]["pass"],
        )

        if ssh.comm:
            dev._cache["ssh_session"] = ssh
            exit_handler.register(dev._cache["ssh_session"].disconnect, "CONNECTION")
            # TODO: actually fingerprint this with a command
            return True
        else:
            ssh.disconnect()
            return False

    @classmethod
    def _verify_https(cls, dev: DeviceData) -> bool:
        port = dev.options["https"]["port"]
        timeout = dev.options["https"]["timeout"]

        cls.log.debug(
            f"Verifying FortiGate HTTPS for {dev.ip}:{port} (timeout: {timeout})"
        )

        http = HTTP(
            ip=dev.ip,
            port=port,
            timeout=timeout,
            dev=dev,
            protocol="https",
        )

        resp = http.get("/")

        if resp and "fortigate" in resp.text.lower():
            dev._cache["https_session"] = http
            return True

        http.disconnect()
        cls.log.debug(f"FortiGate HTTPS verification failed for {dev.ip}:{port}")
        return False


Fortigate.ip_methods = [
    IPMethod(
        name="Fortigate SSH login",
        description=str(Fortigate._verify_ssh.__doc__).strip(),
        type="unicast_ip",
        identify_function=Fortigate._verify_ssh,
        reliability=6,
        protocol="ssh",
        transport="tcp",
        default_port=22,
    ),
    IPMethod(
        name="Fortigate web page check",
        description=str(Fortigate._verify_ssh.__doc__).strip(),
        type="unicast_ip",
        identify_function=Fortigate._verify_https,
        reliability=8,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
]


__all__ = ["Fortigate"]
