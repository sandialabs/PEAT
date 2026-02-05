"""
Core functionality for interrogating a SEL Real-Time Automation Controller (RTAC).

.. note::
   The 3530 RTAC (and possibly others ) disable ping (ICMP) responses by default.
   If using PEAT against an RTAC on another subnet or VLAN and the online check
   fails, try again with the ``--assume-online`` flag set. Another option is to
   force TCP SYN checks to be used with port 443.

SEL RTACs store data in a PostgreSQL database, but it can be exported as XML.
Each "page" of the RTAC configuration is its own XML file.
Instead of importing all of the XML files separately, they should be put into
a tarball. PEAT will then decompress it to the file system, read each file
into memory, sort based on file type, and finally delete the files from the file
system. PEAT can then parse the configuration based on what's in-memory.

To test Postgres (connecting to the "3530" database table):
``psql -h <ip> -U <username> -d 3530``

Note: Nginx is the web server used by the SEL RTAC devices.

Listening network services

- HTTP (TCP 80) (This redirects to 443 HTTPS)
- HTTPS (TCP 443)
- PostgreSQL (TCP 5432)

Supported models

- SEL-3530
- SEL-3530-4
- SEL-3350

Authors

- Ryan Vrecenar
- Christopher Goes
"""

import base64
import functools
import math
import re
import tarfile
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path
from time import sleep
from typing import Literal

import psycopg2

from peat import (
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    datastore,
    exit_handler,
    state,
    utils,
)
from peat.consts import DeviceError
from peat.data.data_utils import merge_models
from peat.data.models import User
from peat.data.validators import validate_hash
from peat.protocols import HTTP

from .rtac_parse import (
    parse_accesspointrouters,
    parse_contact_ios,
    parse_devices,
    parse_maincontroller,
    parse_pous,
    parse_systemtags,
    parse_tagprocessor,
)
from .sel_consts import RTAC_DB_NAME, RTAC_DB_TABLES, RTAC_TRANSIENT_KEYS
from .sel_http import SELHTTP


class SELRTAC(DeviceModule):
    """
    SEL Real-Time Automation Controller (RTAC).
    """

    device_type = "RTAC"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"

    can_parse_dir = True
    filename_patterns = [
        # "*.tar.gz"
        "*accesspointrouter*.tar.gz",
        "*AccessPoints*.tar.gz",
        "devices.tar.gz",
        "*rtacexport*.tar.gz",  # rtacexport3.tar.gz
        "*rtac*.tar*",
        "*rtac*.tgz",
        "Tag Processor.xml",
        "SystemTags.xml",
        "Main Controller.xml",
        "Contact I_O.xml",
    ]

    # These are what's known to work. Others may work as well
    supported_models = ["3530", "3530-4", "3350"]
    module_aliases = [f"sel-{x}" for x in supported_models]

    default_options = {
        "web": {
            "user": "",
            "pass": "",
            "users": [
                "Admin",
                "admin",
                "administrator",
            ],
            "passwords": ["admin", "rtac"],
        },
        "postgres": {
            "user": "",
            "pass": "",
            "users": ["Admin", "admin", "administrator", "rtac"],
            "passwords": ["admin", "rtac"],
        },
        "sel": {
            "pull_http": True,
            "pull_postgres": True,
            "rtac_monitor_enable": False,
            "rtac_monitor_count": 3,
            "rtac_monitor_pause_for": 4.0,
        },
    }

    _tag_to_parser_map = {
        "AccessPointRouter": parse_accesspointrouters,
        "Device": parse_devices,
        "TagProcessor": parse_tagprocessor,
        "ContactIO": parse_contact_ios,
        "SystemTags": parse_systemtags,
        "MainController": parse_maincontroller,
        "POU": parse_pous,
    }

    @classmethod
    def _verify_http(
        cls, dev: DeviceData, protocol: Literal["http", "https"] = "http"
    ) -> bool:
        """
        Verify a device is a SEL RTAC via the HTTP web interface.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.debug(
            f"Verifying RTAC HTTP for {dev.ip}:{port} using "
            f"{protocol} (timeout: {timeout})"
        )

        session = SELHTTP(dev.ip, port, timeout)
        logged_in = False

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            logged_in = session.login_rtac(
                dev._cache["verified_web_user"],
                dev._cache["verified_web_pass"],
                protocol,
            )
        # Check all user, and pass, only proceed when logged_in is True, or exhausted
        else:
            if dev.options["web"]["user"]:
                users = [dev.options["web"]["user"]]
            else:
                users = dev.options["web"]["users"]

            if dev.options["web"]["pass"]:
                passwords = [dev.options["web"]["pass"]]
            else:
                passwords = dev.options["web"]["passwords"]

            for username in users:
                cls.log.debug(
                    f"Attempting RTAC login to {dev.ip} with user '{username}'"
                )

                for password in passwords:
                    logged_in = session.login_rtac(username, password, protocol)
                    if logged_in:
                        dev._cache["verified_web_user"] = username
                        dev._cache["verified_web_pass"] = password
                        dev.related.user.add(username)
                        break

                if logged_in:
                    break

        if logged_in:
            try:
                dashboard = session.view_dashboard(dev)
            except Exception:
                cls.log.exception(f"Failed to view dashboard for {dev.ip}")
                session.disconnect()
                return False

            # Check if dashboard has appropriate fields
            if (
                (not dashboard.get("web_device_info"))
                or ("Firmware Version" not in dashboard["web_device_info"])
                or ("Host Name" not in dashboard["web_device_info"])
            ):
                session.disconnect()
                return False

            # Only cache session of it's a known RTAC
            if any(m in dev.description.model for m in cls.supported_models) or (
                "3530" in dashboard["web_device_info"].get("Firmware Version", "")
                and "3530" in dashboard["web_device_info"].get("Host Name", "")
            ):
                # Cache the session using this protocol
                # TODO: we should try to prefer HTTPS when possible for security
                if not dev._cache.get("web_session"):
                    dev._cache["web_session"] = session
                    dev._cache["web_protocol"] = protocol
                    exit_handler.register(session.disconnect, "CONNECTION")
                else:
                    session.disconnect()
                return True

        session.disconnect()
        cls.log.debug(f"RTAC HTTP verification failed for {dev.ip}:{port}")
        return False

    @classmethod
    def _verify_https_ssl_certificate(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL RTAC via inspection of the Common Name
        attribute of a SSL certificate.
        """
        timeout = dev.options["https"]["timeout"]
        port = dev.options["https"]["port"]

        cls.log.debug(f"Verifying {dev.ip}:{port} using SSL (timeout: {timeout})")

        with HTTP(dev.ip, port, timeout, dev=dev) as http:
            parsed_cert = http.get_ssl_certificate()

        if not parsed_cert:
            return False

        merge_models(dev.x509, parsed_cert)

        entity = parsed_cert.subject
        if not entity.common_name:
            entity = parsed_cert.issuer
        if not entity.common_name:
            return False

        dev._cache["selrtac_ssl_fingerprinted"] = True

        if "SEL" in entity.common_name and "RTAC" in entity.common_name:
            cls.log.debug(f"SSL verification successful for {dev.ip}:{port}")
            dev.description.model = entity.common_name.partition(" ")[0].partition("-")[
                2
            ]
            dev.type = "RTAC"
            cls.update_dev(dev)
            return True

        return False

    @classmethod
    def _verify_postgres(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL RTAC via a PostgreSQL database connection.
        """
        # TODO: cache the connection in dev._cache
        conn = None
        curs = None
        try:
            # If we have a working password from logging in web
            try:
                user = dev.options["postgres"]["user"]
                if not user:
                    user = dev._cache.get("verified_pg_user")
                if not user:
                    user = "postgres"
                kwargs = {
                    "host": dev.ip,
                    "port": dev.options["postgres"]["port"],
                    "dbname": RTAC_DB_NAME,
                    "user": user,
                }
                if dev.options["postgres"]["pass"]:
                    kwargs["password"] = dev.options["postgres"]["pass"]
                elif dev._cache.get("verified_pg_pass"):
                    kwargs["password"] = dev._cache["verified_pg_pass"]
                conn = psycopg2.connect(**kwargs)
                curs = conn.cursor()
            except BaseException:  # Always cleanup regardless of error
                if conn is not None:
                    conn.close()
                return False

            # No valid logged in session created
            if conn is None:
                return False

            dev._cache["verified_pg_user"] = kwargs["user"]
            dev.related.user.add(kwargs["user"])
            if "password" in kwargs:
                dev._cache["verified_pg_pass"] = kwargs["password"]

            cmd = "SELECT * from device_info;"
            curs.execute(cmd)
            conn.commit()

            # if no columns in table continue
            if curs.description is None:
                curs.close()
                conn.close()
                return False

            data = curs.fetchall()
            cols = [desc[0] for desc in curs.description]
            for datum in data:
                for col_idx in range(len(cols)):
                    if "3530" in datum[col_idx]:
                        curs.close()
                        conn.close()
                        return True
            curs.close()
            conn.close()
        except Exception:
            cls.log.exception("CLEANED UP")
            if curs is not None:
                curs.close()
            if conn is not None:
                conn.close()
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # Ensure postgres cursor and connection is properly cleaned up on exit
        # TODO: better way of ensuring postgres connections are cleaned up
        def _ensure_close_db():
            for k in ["pg_cursor", "pg_conn"]:
                if dev._cache.get(k):
                    try:
                        dev._cache[k].close()
                    except Exception:
                        pass

        exit_handler.register(_ensure_close_db, "CONNECTION")

        # Pull and compare history over time
        if dev.options["sel"]["rtac_monitor_enable"]:
            pull_count = dev.options["sel"]["rtac_monitor_count"]
            pause_time = dev.options["sel"]["rtac_monitor_pause_for"]
            cls.log.info(
                f"Pulling {pull_count} times with a pause for "
                f"{pause_time:.2f} seconds between each pull"
            )
            dev._cache["history"] = {}

            for i in range(2, pull_count):
                try:
                    cls.log.info("Pulling config")
                    cls.log.info(f"\tRecording history {i}")
                    cls.update_history(dev)
                    sleep(dev.options["sel"]["rtac_monitor_pause_for"])
                    cls.log.info("\tChecking history")
                    cls.check_history(dev)
                except Exception:
                    cls.log.exception(f"failed history check of {dev.ip}")
                    return False

            return True

        # Regular pull and return
        cls.pull_config(dev)
        return True

    # --------- Monitor Functionality ---------
    @classmethod
    def chk_transient_path(cls, path: list[str]) -> bool:
        """Check if path is defined in transient keys."""
        for key in RTAC_TRANSIENT_KEYS:
            i = 0
            # if lengths do not match, proceed
            if not len(key) == len(path):
                continue

            # assume match is true, until proven otherwise
            match = True
            # iterate over whitelist keys to compare
            for pattern in key:
                if re.match(pattern, path[i]) is None:
                    match = False
                    break
                i += 1
            if match is True:
                return True
        return False

    @classmethod
    def compare_dictionaries(
        cls,
        dict_1: dict,
        dict_2: dict,
        dict_1_name: str,
        dict_2_name: str,
        path: list[str] | None = None,
        err: list[str] | None = None,
        key_err: list[str] | None = None,
        value_err: list[str] | None = None,
    ) -> tuple[list[str], list[str], list[str]]:
        if err is None:
            err = []
        if key_err is None:
            key_err = []
        if value_err is None:
            value_err = []

        for k1, v1 in dict_1.items():
            if path is None:
                old_path = []
            else:
                old_path = path[:]
            old_path.append(f"{k1}")
            # Check if test path in transient keys
            if cls.chk_transient_path(old_path):
                continue
            if k1 not in dict_2:
                key_err.append(f"Key {dict_2_name}{old_path} not in {dict_2_name}\n")
            else:
                if isinstance(v1, dict) and isinstance(dict_2[k1], dict):
                    cls.compare_dictionaries(
                        v1, dict_2[k1], "d1", "d2", old_path[:], err, key_err, value_err
                    )
                else:
                    if v1 != dict_2[k1]:
                        value_err.append(
                            f"Value of {dict_1_name}{old_path} ({v1}) not same "
                            f"as {dict_2_name}{old_path} ({dict_2[k1]})\n"
                        )

        for k in dict_2.keys():
            if path is None:
                old_path = []
            else:
                old_path = path[:]
            old_path.append(f"{k}")
            if k not in dict_1:
                key_err.append(f"Key {dict_2_name}{old_path} not in {dict_1_name}\n")

        return key_err, value_err, err

    @classmethod
    def update_history(cls, dev: DeviceData) -> None:
        cls.pull_config(dev)
        timestamp = utils.utc_now().strftime("%Y-%m-%dT%H:%M:%S")
        dev._cache["history"][timestamp] = deepcopy(dev.extra)
        dev.extra = {}

    @classmethod
    def check_history(cls, dev: DeviceData) -> None:
        if len(dev._cache["history"].keys()) < 2:
            cls.log.info("baselined.")
            return
        d1_name: str = list(dev._cache["history"].keys())[-1]
        d2_name: str = list(dev._cache["history"].keys())[-2]
        d1 = dev._cache["history"][d1_name]
        d2 = dev._cache["history"][d2_name]
        cls.log.info(f"Comparing dictionaries '{d1_name}' and '{d2_name}'")
        res1 = cls.compare_dictionaries(d1, d2, "d1", "d2")
        res2 = ([], [], [])
        if (res1[0] == [] and res1[1] == [] and res1[2] == []) and (
            res2[0] == [] and res2[1] == [] and res2[2] == []
        ):
            cls.log.info("nominal")
        else:
            cls.log.error("abnominal")
            if state.elastic:
                # update action to key that is changed
                state.elastic.push(
                    "alerts",
                    {
                        "message": "device configuration changed",
                        "event": {
                            "action": "config-change",
                            "category": "device-config-change",
                            "kind": {"alert"},
                            "module": cls.__name__,  # "SELRTAC"
                            "severity": 10,
                        },
                    },
                )

    @classmethod
    def pull_config(cls, dev: DeviceData) -> None:
        """Pull and parse configuration from an RTAC."""
        # NOTE: this method is used by update_history() and _pull()
        # NOTE: if web pull fails, attempt postgres pull anyway to make sure we get data
        web_exception = None
        if dev.options["sel"]["pull_http"]:
            try:
                cls.pull_web(dev)
                cls.update_dev(dev)
            except Exception as ex:
                cls.log.exception(f"failed http pull from {dev.ip}")
                state.error = True
                web_exception = ex
        else:
            cls.log.warning(f"Skipping HTTP pull from {dev.ip} (sel.pull_http=False)")

        if dev.options["sel"]["pull_postgres"]:
            cls.pull_postgres(dev)
            cls.update_dev(dev)
        else:
            cls.log.warning(
                f"Skipping postgres pull from {dev.ip} (sel.pull_postgres=False)"
            )

        # NOTE: exceptions are handled by pull_api, it doesn't check method
        # return status at the moment, so we re-raise web exception here.
        if web_exception:
            raise web_exception from None

    @classmethod
    def pull_web(cls, dev: DeviceData, protocol: str | None = None) -> dict | None:
        cls.log.info(f"Pulling RTAC data via web interface from {dev.ip}")

        if not protocol:
            protocol = dev._cache.get("web_protocol", "http")

        if not dev._cache.get("web_protocol"):
            dev._cache["web_protocol"] = protocol

        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        if not dev._cache.get("web_session"):
            cls.log.info(f"No web session cached for {dev.ip}, creating new session...")
            dev._cache["web_session"] = SELHTTP(dev.ip, port, timeout)

        session = dev._cache["web_session"]
        if not session.rtac_logged_in:
            username = dev._cache.get("verified_web_user")
            if not username:
                username = dev.options["web"]["user"]
            if not username:
                username = "ACC"
            password = dev._cache.get("verified_web_user")
            if not password:
                password = dev.options["web"]["pass"]
            if not password:
                password = "OTTER"
            if not session.login_rtac(username, password, protocol):
                cls.log.error(
                    f"Failed to login to web interface on "
                    f"{dev.ip} with user '{username}'"
                )
                return None
            dev.related.user.add(username)

        web_methods = [
            session.view_dashboard,
            session.view_usagepolicy,
            session.view_filesondevice,
            session.view_features,  # TODO: not working currently
            session.view_accounts,  # NOTE: added to pull
            session.view_user_roles,
            session.view_ldap,
            session.download_http_files,
            session.view_ip_tables,  # TODO: not implemented yet
            session.view_syslog,  # this is slowest, do last
        ]

        cls.log.info(
            f"Completed web session setup, beginning pull from "
            f"{dev.ip}:{port} using {len(web_methods)} web methods"
        )

        pulled_config = {}
        dev._cache["num_successful_methods"] = 0

        for method in web_methods:
            sleep(0.3)  # attempt to avoid overloading web server

            cls.log.info(f"Running '{method.__name__}' for {dev.ip}:{port}")
            try:
                method_result = method(dev)  # type: dict

                if not method_result or not any(
                    bool(val) for val in method_result.values()
                ):
                    cls.log.warning(
                        f"No data from HTTP method '{method.__name__}' "
                        f"on {dev.ip}:{port}"
                    )
                else:
                    pulled_config.update(method_result)
                    dev._cache["num_successful_methods"] += 1
            except Exception:
                cls.log.exception(f"'{method.__name__}' failed on {dev.ip}:{port}")
                continue

        if dev._cache["num_successful_methods"] == 0:
            dev._cache["web_session"].disconnect()
            raise DeviceError(f"all web methods failed from {dev.ip}")

        cls.log.info(
            f"Finished pulling data via web interface from {dev.ip}:{port} "
            f"({dev._cache['num_successful_methods']} methods were "
            f"successful out of {len(web_methods)} methods attempted)"
        )

        dev.write_file(pulled_config, "pulled-web-config.json")

        # Close the web session
        dev._cache["web_session"].disconnect()

        # Remove fields we don't want in elasticsearch
        for bad_field in ["web_syslog_events", "web_usagepolicy", "web_device_info"]:
            if bad_field in pulled_config:
                del bad_field

        return pulled_config

    @classmethod
    def pull_postgres(cls, dev: DeviceData) -> dict | None:
        cls.log.info(f"Pulling postgres data from {dev.ip}")

        if not dev._cache.get("pg_conn"):  # TODO: check if connected
            username = dev._cache.get("verified_pg_user")
            if not username:
                username = dev.options["postgres"]["user"]
            if not username:
                username = "postgres"
            dev.related.user.add(username)
            password = dev._cache.get("verified_pg_pass")
            if not password:
                password = dev.options["postgres"]["pass"]

            dev._cache["pg_conn"] = psycopg2.connect(
                host=dev.ip,
                dbname=RTAC_DB_NAME,
                user=username,
                password=password,
                port=dev.options["postgres"]["port"],
            )
            # TODO: check if login succeeded, if not return None

        conn = dev._cache["pg_conn"]
        if not dev._cache.get("pg_cursor"):  # TODO: check if connected
            dev._cache["pg_cursor"] = conn.cursor()
        cursor = dev._cache["pg_cursor"]

        config = {}

        for table in RTAC_DB_TABLES:
            config[table] = {}
            command = f"SELECT * from {table};"
            cls.execute(cursor, command)
            conn.commit()

            # if no columns in table continue
            if cursor.description is None:
                continue
            data = cursor.fetchall()
            cols = [desc[0] for desc in cursor.description]
            for datum in data:
                config[table][datum[0]] = {}
                for col_idx in range(len(cols)):
                    # do conversions based on column label
                    if cols[col_idx] == "data" or cols[col_idx] == "project_image":
                        # if binary blob, hash binary blob
                        if datum[col_idx] is None:
                            config[table][datum[0]][cols[col_idx]] = ""
                            continue
                        # TODO: should we save hash in one place and raw in another?
                        decoded = (base64.b64encode(datum[col_idx].tobytes())).decode()
                        config[table][datum[0]][cols[col_idx]] = decoded
                    elif cols[col_idx] in [
                        "set_dst_start_time",
                        "set_dst_stop_time",
                        "set_system_time_dst_start_time",
                        "set_system_time_dst_stop_time",
                        "last_access",
                        "account_creation",
                        "last_modified_time",
                    ]:
                        # if datetime object, convert to string
                        # TODO: use utils.parse_date().isoformat()
                        # to generate ISO-format time string.
                        config[table][datum[0]][cols[col_idx]] = str(datum[col_idx])
                    elif cols[col_idx] == "new_event_reset_location_value":
                        # if floating point object, and NaN, then convert to -999999
                        val = datum[col_idx]
                        if not math.isfinite(datum[col_idx]):
                            val = float(-999999999)
                        config[table][datum[0]][cols[col_idx]] = val
                    else:
                        config[table][datum[0]][cols[col_idx]] = datum[col_idx]

        # TODO: compare device data with what's pulled from web and emit warning if it differs
        #  e.g. firmware rev, checksums, etc.
        dev_info = config.get("device_info")
        if dev_info:
            if len(dev_info) > 1:
                cls.log.warning(
                    f"Multiple devices found in PostgreSQL data "
                    f"in 'device_info' from {dev.ip}: {dev_info}"
                )

            first = next(iter(dev_info.values()))

            host_name = first.get("host_name")
            if host_name and not dev.hostname:
                dev.hostname = host_name
            dev.related.hosts.add(host_name)

            dev_name = first.get("device_name")
            if dev_name and not dev.name:
                dev.name = dev_name
            dev.related.hosts.add(dev_name)

            location = first.get("location")  # TODO: is this lat/lon?
            if location and not dev.geo.name:
                dev.geo.name = location

            dev.extra["postgres_device_info"] = dev_info
            fw_checksum = first.get("current_fw_checksum")
            if fw_checksum:
                if not dev.firmware.checksum:
                    dev.firmware.checksum = fw_checksum
                # This may or may not be an actual hash, and in some
                # cases it's definitely not, e.g. "B0AB".
                try:
                    checksum_hash = validate_hash(fw_checksum)
                    dev.related.hash.add(checksum_hash)
                    if not dev.firmware.hash.md5 and len(fw_checksum) == 32:
                        dev.firmware.hash.md5 = checksum_hash
                except ValueError:
                    pass
            desc = first.get("description")
            if desc and not dev.description.description:
                dev.description.description = desc
            fw_rev = first.get("fw_release_version")
            if fw_rev and not dev.firmware.revision:
                dev.firmware.revision = fw_rev

        projects = config.get("projects", {})
        if projects:
            if len(projects) > 1:
                cls.log.warning(
                    f"{len(projects)} projects on {dev.ip}, using "
                    f"metadata from first one to populate "
                    f"fields for 'host.logic'"
                )

            projs = list(projects.values())
            if not projs:
                cls.log.error(f"Failed to get a project for {dev.ip}")
                state.error = True
            else:
                proj = projs[0]
                dev.logic.name = proj["project_name"]
                dev.logic.description = proj["description"]
                dev.related.user.add(proj["last_modified_user"])
                if not dev.logic.author:
                    dev.logic.author = proj["last_modified_user"]
                dev.logic.last_updated = utils.parse_date(proj["last_modified_time"])

        # Add device names from "remote_devices"
        # TODO: models
        # "32": {
        #     "remote_device_id": 32,
        #     "project_id": 1,
        #     "name": "SEL_411L_E1",
        #     "model": "411L",
        #     "version_hash": null,
        #     "manufacturer": null,
        #     "version": null
        # },
        remote_devices = config.get("remote_devices", {})
        for rem_dev in remote_devices.values():
            # Skip tunnels, e.g "Eng_Access_40"
            if "Eng_Access_" not in rem_dev["name"]:
                dev.related.hosts.add(rem_dev["name"])

        # "role_master" and "system_roles" have almost the same format
        for role_key in ["role_master", "system_roles"]:
            # TODO: system_roles has a "unix_home_dir" value, useful?
            role_dict = config.get(role_key)
            if role_dict:
                for rv in role_dict.values():
                    # Note: db_name usually matches name, and
                    # lc_name is lowercase version of name.
                    for key in ["name", "lc_name", "db_name"]:
                        if rv.get(key):
                            dev.related.roles.add(rv[key])

        root_devices = config.get("root_devices")
        if root_devices:
            for rd in root_devices.values():
                if rd.get("name"):
                    dev.related.hosts.add(rd["name"])

        # TODO:
        #   role_master
        #   role_membership
        #   system_permissions
        #   system_role_resource_assoc
        #   system_roles
        #   user_lockouts
        #   user_membership

        users = config.get("users", {})
        for user_dict in users.values():
            user = User()

            # Values could be null, so gotta check
            if user_dict.get("description"):
                user.description = user_dict["description"]
            if user_dict.get("username"):
                user.name = user_dict["username"]

            for extra_key in [
                "user_id",
                "status",
                "account_creation",
                "last_access",
                "account_expiration",
                "auto_login",
            ]:
                if user_dict.get(extra_key) is not None:
                    user.extra[extra_key] = str(user_dict[extra_key])

            dev.store("users", user, lookup="name")

        users_transient_history = config.get("users_transient_history", {})
        for user_dict in users_transient_history.values():
            dev.related.user.add(user_dict.get("username", ""))

        serial_ports = config.get("serial_ports", {})  # type: dict
        for sp in serial_ports.values():
            extra = {}

            for m_key in [
                "connection_method_id",
                "protocol_id",
                "serial_port_type_id",
            ]:
                if sp.get(m_key):
                    extra[m_key] = str(sp[m_key])

            if "full_duplex" in sp:
                extra["full_duplex"] = bool(sp["full_duplex"])

            flow_control = ""  # "none"
            for fc_key in ["hardware_flow_control", "software_flow_control"]:
                if sp.get(fc_key):
                    flow_control = fc_key

            s_type = "serial"
            s_port_id = str(sp.get("serial_port_type_id", ""))
            if s_port_id == "232":
                s_type = "rs-232"

            iface = Interface(
                connected=bool(sp.get("port_power")),
                name=str(sp.get("device_file", "")),
                type=s_type,
                id=str(sp.get("serial_port_id", "")),
                serial_port=str(sp.get("device_file", "")),
                baudrate=int(sp.get("baud_rate")) if "baud_rate" in sp else None,
                data_bits=int(sp.get("data_bits")) if "data_bits" in sp else None,
                # TODO: determine parity value
                stop_bits=int(sp.get("stop_bit")) if "stop_bit" in sp else None,
                flow_control=flow_control,
                extra=extra,
            )

            dev.store("interface", iface, lookup="serial_port")

        for conn_group_name in [
            "local_tcp_network_port_connections",
            "local_udp_network_port_connections",
        ]:
            conn_group = config.get(conn_group_name, {})  # type: dict
            for conn_value in conn_group.values():
                for port_key in ["tcp_port", "udp_port"]:
                    if conn_value.get(port_key):
                        dev.related.ports.add(int(conn_value[port_key]))

        # If protocol_id isn't null, it may be of interest
        for port_group_name in [
            "local_tcp_network_ports",
            "local_udp_network_ports",
        ]:
            port_group = config.get(port_group_name, {})  # type: dict
            for port_values in port_group.values():
                if port_values.get("protocol_id") and port_values.get("port_number"):
                    dev.related.ports.add(int(port_values["port_number"]))

        # Pull some useful info out of various setting groups
        for eth_group_name in [
            "dnp_client_ethernet_settings",
            "dnp_client_unique_settings",
            "sel_client_ethernet_settings",
            # NOTE: this section is untested
            "modbus_ethernet_settings",
        ]:
            dnp_group = config.get(eth_group_name, {})  # type: dict
            for eth_settings in dnp_group.values():
                if eth_settings.get("server_ip_address"):
                    dev.related.ip.add(eth_settings["server_ip_address"])

                for port_key in [
                    "server_ip_port",
                    "local_tcp_port",
                    "local_udp_port",
                    "client_udp_port",
                ]:
                    if eth_settings.get(port_key):
                        dev.related.ports.add(int(eth_settings[port_key]))

                # This only appears in dnp_client_ethernet_settings
                if eth_settings.get("ssh_username"):
                    dev.related.user.add(eth_settings["ssh_username"])

        # config is large and leads to excessive-sized device-data-summary.json

        # Can't save as JSON, too large and has some data types that are not human-reader friendly
        dev.write_file(config, "raw-pulled-postgres-config.txt")
        del config["tag_task_settings"]
        del config["tags"]
        dev.write_file(config, "pulled-postgres-config.json")

        cursor.close()  # TODO: set cache to None?
        conn.close()  # TODO: set cache to None?

        cls.log.debug(f"Finished pulling postgres data from {dev.ip}")
        return config

    @classmethod
    def execute(cls, cursor, statement: str, args: tuple | None = None) -> None:
        """Wrapper code for database execute."""
        if args is None:
            args = ()
        while True:  # TODO: change to better method than while loop
            try:
                cursor.execute(statement, args)
            except Exception as e:
                # if the db is locked, try again
                cls.log.trace2(f"Postgres operational error: {e}")
                sleep(0.1)
            # break out when successful
            break

    @classmethod
    def parse_xml(cls, data: str, filename: str, device_info: dict):
        xml_root = ET.fromstring(data)
        tag = xml_root[0].tag
        if tag in cls._tag_to_parser_map:
            cls._tag_to_parser_map[tag](xml_root, device_info)
        else:
            cls.log.debug(f"Skipping unknown XML file '{filename}' with tag '{tag}'")

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        if not dev:
            dev = datastore.get(file.name.partition(".")[0], "id")

        device_info = {}

        # Possible inputs:
        # - .tar.gz/.tar file containing XML files
        # - directory of XML files
        # - single XML file?
        #
        # NOTE: all RTAC XML files must be read with encoding "utf-8-sig".
        # The RTAC editor appears to save XML files as "UTF-8 with BOM" encoding.
        # The XML parser handles this fine on Linux, but for some reason it
        # isn't handled well on Windows. This is fixed by decoding the text
        # using the "utf-8-sig" encoding, which will skip the BOM if present.
        # Per the Python documentation:
        #   "On decoding utf-8-sig will skip those three bytes if they appear
        #   as the first three bytes in the file."
        # Ref: https://docs.python.org/3/library/codecs.html#encodings-and-unicode
        if file.is_dir():
            xml_files = file.rglob("*.xml")
            for xf in xml_files:
                cls.parse_xml(xf.read_text(encoding="utf-8-sig"), xf.name, device_info)
                dev.related.files.add(xf.name)
        elif file.suffix == ".xml":
            cls.parse_xml(file.read_text(encoding="utf-8-sig"), file.name, device_info)
            dev.related.files.add(file.name)
        elif tarfile.is_tarfile(file):
            if any("gz" in s for s in file.suffixes):
                mode = "r:gz"
            else:
                mode = "r"  # transparent, i think this auto-determines compression

            device_info["existing_files"] = []
            with tarfile.open(name=file.as_posix(), mode=mode, encoding="utf-8") as tar:
                for member in tar.getmembers():
                    cls.log.debug(f"Parsing '{member.name}' from '{file.name}'")
                    f_handle = tar.extractfile(member)

                    if f_handle is not None:  # skip directories
                        device_info["existing_files"].append(member.name)
                        # see note earlier in code about utf-8-sig encoding
                        data = f_handle.read().decode(encoding="utf-8-sig")

                        try:
                            cls.parse_xml(data, member.name, device_info)
                        except Exception as ex:
                            # still save the data to file even if parsing failed
                            cls.log.error(
                                f"Failed to parse '{member.name}' from '{file.name}': {ex}"
                            )

                        dev.write_file(data, f"extracted_files/{member.name}")
                        dev.related.files.add(Path(member.name).name)

        # TODO: there is useful information being parsed we're not saving yet
        #   Interfaces (Ethernet, serial, and USB)
        #   Services (e.g. SSH, Telnet, SEL FastMessage)
        #   Remote device endpoints and registers (Device)
        #       Get a DeviceData from datastore, then update:
        #           registers, IP, services, interfaces, model/brand/vendor
        #   Internal Tags?
        dev.extra.update(device_info)

        # TODO: hack, defaulting model to 3530 for now (it's not being extracted...)
        if not dev.description.model:
            cls.log.warning(
                "RTAC parsing doesn't currently extract the model, "
                "it defaults to '3530' for the time being"
            )
            dev.description.model = "3530"

        cls.update_dev(dev)

        return dev


SELRTAC.ip_methods = [
    IPMethod(
        name="SEL RTAC login HTTP",
        description=str(SELRTAC._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRTAC._verify_http, protocol="http"),
        reliability=6,  # Modern RTACs just redirect from HTTP to HTTPS
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="SEL RTAC login HTTPS",
        description=str(SELRTAC._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRTAC._verify_http, protocol="https"),
        reliability=8,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="SEL RTAC SSL certificate",
        description=str(SELRTAC._verify_https_ssl_certificate.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRTAC._verify_https_ssl_certificate,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="SEL RTAC login PostgreSQL",
        description=str(SELRTAC._verify_postgres.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRTAC._verify_postgres,
        reliability=5,
        protocol="postgres",
        transport="tcp",
        default_port=5432,  # TODO: don't auto scan for postgres
        # TODO: better workaround for postgres port identification
        #   The TCP SYN check may put the database in a weird state or ban us
        #   since the relay's server is configured with a strict limit on connections,
        #   and the port check counts as a new connection.
        #   Implement a custom port_function?
    ),
]


__all__ = ["SELRTAC"]
