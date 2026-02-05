"""
Retrieve and extract data via HTTP from SEL devices.

Authors

- Aidan Kollar
- Amanda Gonzales
- Christopher Goes
- Idaho National Lab
- Jason Hall
- Jessica Robinson
- Ryan Vrecenar
"""

import re
from time import sleep
from typing import Literal
from urllib.parse import urljoin

import humanfriendly
from bs4 import BeautifulSoup
from dateutil.parser import parse as date_parse
from requests import Response

from peat import DeviceData, Event, PeatError, config, consts, datastore, log, utils
from peat.data.models import User
from peat.data.validators import validate_hash
from peat.protocols import HTTP, split_ipv4_cidr

from .relay_parse import (
    parse_and_process_events,
    parse_status_output,
    process_fid,
    process_info_into_dev,
    process_port_settings,
    split_lines,
)


class SELHTTP(HTTP):
    """
    HTTP scraper for SEL devices.

    Models supported: 3530 RTAC and 351, 351S and 451 relays.
    """

    def __init__(self, *args, **kwargs) -> None:
        self._rando: str = ""  # "rando" field from 'input' login page element
        self._session_url: str = ""
        self._url_parts: tuple[str, str] | None = None
        self._found_url: bool = False
        self._port_args_len: int | None = None
        self._logic_page_style: str | None = None
        self.successful_creds: tuple[str, str] | None = None
        self.rtac_l1_user: str = "acc"
        self.session_id: str = ""
        self.rtac_logged_in: bool = False
        self.relay_logged_in: bool = False
        super().__init__(*args, **kwargs)

    @property
    def _rtac_session(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "session_username": self.rtac_l1_user,
        }

    def disconnect(self) -> None:
        if self.rtac_logged_in and self._session:
            self.rtac_log_out()
        super().disconnect()

    def login(
        self,
        user: str = "ACC",
        passwd: str = "OTTER",
        protocol: Literal["http", "https"] = "http",
    ) -> bool:
        """
        Attempt to login to a relay's HTTP server and get a session.

        If the login succeeds, the credentials are stored in the
        ``successful_creds`` class variable and :obj:`True` is returned.

        .. warning::
           This method is NOT to be used for SEL RTACs.
           Instead, use :meth:`~peat.modules.sel.sel_http.SELHTTP.login_rtac`

        Args:
            user: Username to use for login
            passwd: Password to use for login
            protocol: HTTP protocol to use ('http' or 'https')

        Returns:
            If the login was successful
        """
        self.log.debug(f"Attempting login via {protocol}")

        # Get index.html or whatever the root page is
        page = self.get(protocol=protocol, use_cache=True)
        if not page:
            self.log.warning("Login failed: could not get login page")
            return False

        # TODO: if "2AC" is in the login page script, it's probably a 351S
        #   Tested two 451's and neither has it
        soup = self.gen_soup(page.content)
        input_element = soup.find("input", type="hidden")

        if not input_element:
            input_element = soup.find("input")

        if not input_element:
            self.log.debug("Failed to find 'input' field in login page")
            self.log.trace2(f"** Page data **\n{repr(page.content)}\n")
            return False

        # set protocol now that we know it worked
        self.protocol = protocol

        self._rando = str(input_element.get("value"))
        self.log.trace2(f"Rando: {self._rando}")

        # TODO: 351S allows login to level 2
        login_data = {"usrid": user, "pswd": passwd, "rando": self._rando}

        login_url = f"{self.url}/login"
        self.log.trace(f"Sending login POST request to {login_url}")
        resp = self.session.post(url=login_url, data=login_data, timeout=self.timeout)

        if not resp or resp.status_code != 200:
            self.log.error(
                f"Login failed: bad response "
                f"({resp.status_code if resp else 'No response'})"
            )
            return False

        # 351S has "login.html"
        # 451 has "login_query.html"
        # 351 has "login"
        self.log.trace(f"Response URL: {resp.url}")
        sess_url = (
            resp.url.replace("login_query.html", "")
            .replace("login.html", "")
            .replace("login", "")
        )

        self.log.trace(f"Intermediate session URL: {sess_url}")

        if "error=invalid" in sess_url:
            self.log.error(f"Login failed: invalid credentials for user '{user}'")
            return False

        # 351 doesn't include the magic in the response
        if "/N" not in sess_url:
            soup = self.gen_soup(resp.content)
            magic = soup.find("a")["href"].replace("ver.html", "")
            sess_url += magic[1:]

        # 451 (351S includes "protected" in the response url)
        if "protected/" not in sess_url:
            sess_url = sess_url.replace("/N", "/protected/N")

        self._session_url = sess_url
        self.log.trace(f"Final session URL: {self._session_url}")

        self.successful_creds = user, passwd
        self.relay_logged_in = True

        return True

    def read_page(self, cmd: str, param: str | None = None) -> str:
        """
        Creates URL from given cmd and parameter and extracts text data from that page.

        Args:
            cmd: command string for webpage url
            param: command parameters for webpage url

        Returns:
            The relevant page data needed for parsing

        Raises:
            PeatError: if the page read fails. This may be because PEAT can't
                determine the correct command URL format for the device or
                if another error occurs, such as a communication error.
        """
        if not self._url_parts:
            self.log.trace(
                "'_url_parts' attribute is unset, attempting to "
                "determine the proper URL format"
            )

            for parts in [("", ".html"), ("static_command.html?cmd=", "")]:
                try:
                    data = self._get_page(self._gen_url(cmd, parts, param))
                    self._url_parts = parts
                    self._found_url = True
                    self.log.debug(f"Found command URL! Parts: {parts}")
                    return data
                except PeatError:
                    continue

            self._url_parts = None
            raise PeatError(f"could not determine command URL for {self.ip}")

        return self._get_page(self._gen_url(cmd, self._url_parts, param))

    def _get_page(self, url: str) -> str:
        self.log.trace2(f"Getting page: {url}")

        response = self.session.get(url, timeout=self.timeout)

        if response.status_code != 200:
            if self._found_url:
                self.log.debug(
                    f"Code '{response.status_code}' from '{url}'\n\n"
                    f"** Raw response data **\n\n{repr(response.content)}\n"
                )
            raise PeatError(f"session was broken to {self.ip}:{self.port}")

        # Save the raw file to disk as an artifact
        try:
            if response.text:
                dev = datastore.get(self.ip)

                f_name = (
                    "/".join(url.split("/")[3:]).replace("?", "_").replace(":", "_")
                )

                # Ensure the written file ends with ".html"
                # e.g. turn "...static_command.html_cmd=ver"
                # into "...static_command_cmd=ver.html"
                if ".html" in f_name and not f_name.endswith(".html"):
                    f_name = f_name.replace(".html", "")
                    f_name = f"{f_name}.html"

                dev.write_file(
                    data=response.text,
                    filename=f_name,
                    out_dir=dev.get_sub_dir("http_files"),
                )
        except Exception:
            self.log.exception(f"Failed to write page '{url}' to file")

        data = self.parse_page_data(response.content)
        if config.DEBUG >= 4:
            self.log.trace4(f"Data for '{url}': {repr(data)}")

        return data

    def _gen_url(self, cmd: str, parts: tuple[str, str], param: str | None) -> str:
        url = f"{self._session_url}{parts[0]}{cmd}{parts[1]}"
        if param:
            url += f"&param={param}"
        return url

    def parse_page_data(self, content: bytes) -> str:
        """
        Parse raw HTML page data and extract the contents of the ``pre`` section.

        The "pre" tag contains rax HTML text. For the SEL relays, this usually
        contains the output of the command run "under the hood", e.g. "sho p1".
        """
        # TODO: a page may have multiple groups, we need to parse all of them and return as a list
        pre = self.gen_soup(content).find("pre")

        if not pre:
            raise PeatError("Failed to find 'pre' section in page content")

        return pre.string.replace("\r\n", "\n")  # Replace CRLF with LF

    # -------------------- RTAC Web Pages --------------------

    def login_rtac(
        self,
        user: str = "ACC",
        passwd: str = "OTTER",
        protocol: Literal["http", "https"] = "https",
    ) -> bool:
        """
        Login to the HTTP interface for the SEL RTAC.
        This works for 3530, 3530-4, and 3350.

        Note: Nginx is the web server used by the SEL RTAC devices.
        """
        page = self.get("", protocol)
        if not page:
            self.log.warning("Login failed, could not get login page")
            return False

        # NOTE: SEL RTAC does not contain Device ID on front page
        # NOTE: do NOT decode here, it won't handle sites with
        # non-utf8 encodings, e.g. during a PEAT scan.
        # BeautifulSoup4 is able to determine the encoding
        # and process it appropriately.
        soup = self.gen_soup(page.content)

        input_element = soup.find("input", type="hidden")
        if not input_element:
            self.log.debug("Failed to find 'input' field in login page")
            self.log.trace2(f"** Page data **\n{page.content}\n")
            return False
        self._rando = str(input_element.get("value"))

        # set protocol now that we know it worked
        self.protocol = protocol

        login_data = {
            "session_username": user,
            "password": passwd,
            "temp_auth_token": self._rando,
        }
        resp = self.post(f"{self.url}/auth.sel?{querystr()}", params=login_data)
        if not resp or resp.status_code != 200:
            return False

        # 200 can also tell us bad password, check for response,
        # "Failure to login invalid user/pass"
        if "Failure" in resp.text:
            return False

        self.rtac_l1_user = user
        self.session_id = resp.text  # resp.content
        self.rtac_logged_in = True
        self.log.info("Logged in to RTAC")

        return True

    @staticmethod
    def dump_htmltable(html_page: Response, config: dict) -> None:
        tables = read_html(html_page.content)
        # Cleanup keys to remove ":" characters and any stray spaces
        tables = {k.replace(":", " ").strip(): v for k, v in tables.items()}

        # TODO: return dict instead of updating a passed variable
        config.update(tables)

    def get_index(self, dev: DeviceData) -> dict:
        """
        Get the data from the gateway dashboard.
        """
        config = {"web_device_info": {}}
        self.log.info("Getting Gateway index info")
        device_info = self.get(
            page="index.sel",
            protocol="https",
            params=self.cookies,
            dev=dev,
        )
        self.dump_htmltable(device_info, config["web_device_info"])
        version_info = {"Version Information": ""}
        for key in config.get("web_device_info", None):
            if key.startswith("Version Information"):
                versions = key.split("\n")
                for i, info in enumerate(versions):
                    if "FID String" in info:
                        version_info["Firmware Version"] = versions[i + 1]
                        break
                version_info["Version Information"] = key
                break
        version_info["Version Information"].split("\n")
        config["web_device_info"].update(version_info)
        return config

    # TODO: split this function up into 3 separate functions?
    def view_dashboard(self, dev: DeviceData) -> dict:
        """
        Get the data from the RTAC 'dashboard' (``device_info.sel``).
        """
        dash_config = {
            "web_device_info": {},
            "web_diagnostics": {},
            "web_post_summary": {},
            # "web_dashboard_info": {},
        }

        # === Device Info ===
        self.log.info("Getting RTAC device info (device_info.sel)")
        dev_info_response = self.post(
            f"{self.url}/device_info.sel?{querystr()}",
            params=self._rtac_session,
            dev=dev,
        )

        if not dev_info_response or not dev_info_response.content:
            self.log.error("No RTAC device info data (device_info.sel)")
        else:
            try:
                self.dump_htmltable(dev_info_response, dash_config["web_device_info"])
                dev.extra["web_device_info"] = dash_config["web_device_info"]
                # Not useful to include, even in "extra"
                if "Default Home Page" in dev.extra["web_device_info"]:
                    del dev.extra["web_device_info"]["Default Home Page"]
            except ValueError as ex:
                self.log.warning(
                    f"No table in 'device_info': {ex} (check credentials?)"
                )

        # This was previously inside SELRTAC._verify_http()
        web_inf = dash_config["web_device_info"]
        if web_inf:
            if web_inf.get("Host Name"):
                if not dev.name:
                    dev.name = web_inf["Host Name"]
                if not dev.hostname:
                    dev.hostname = web_inf["Host Name"]
                dev.id = web_inf["Host Name"]

            # This sets:
            # - dev.description.model
            # - dev.description.product
            # - dev.firmware (multiple fields, including version)
            if web_inf.get("Firmware Version"):
                process_fid(web_inf["Firmware Version"], dev)

            # NOTE: this was added in RTAC firmware release R152
            # on 2023-11-09: https://selinc.com/api/download/138911/
            if web_inf.get("Firmware Hash"):
                try:
                    upper = web_inf["Firmware Hash"].upper()
                    if "SHA256" in upper:
                        hash_str = upper.split(":")[-1].strip()
                        dev.firmware.hash.sha256 = hash_str
                except Exception as ex:
                    self.log.warning(
                        f"Failed to parse firmware hash '{web_inf['Firmware Hash']}': {ex}"
                    )

            if web_inf.get("BIOS Version"):
                if not dev.boot_firmware.version:
                    dev.boot_firmware.version = web_inf["BIOS Version"]

            if web_inf.get("Firmware Checksum"):
                fw_checksum = web_inf["Firmware Checksum"]
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

            if web_inf.get("Project ID"):
                proj_id = web_inf["Project ID"]
                dev.logic.id = proj_id

                # This may or may not be an actual hash
                try:
                    proj_id_hash = validate_hash(proj_id)
                    dev.related.hash.add(proj_id_hash)
                    if not dev.logic.hash.md5 and len(proj_id_hash) == 32:
                        dev.logic.hash.md5 = proj_id_hash
                except ValueError:
                    pass

            if web_inf.get("Serial Number"):
                dev.serial_number = web_inf["Serial Number"]
            if web_inf.get("Part Number"):
                dev.part_number = web_inf["Part Number"]

            # These were enabled by improvements to HTML parsing
            if web_inf.get("Device Name"):
                dev.name = web_inf["Device Name"]

            if web_inf.get("Device Location"):
                dev.geo.name = web_inf["Device Location"]

            if web_inf.get("Device Description"):
                if not dev.description.description:
                    dev.description.description = web_inf["Device Description"]

        # === Diagnostics ===
        self.log.debug("Getting RTAC diagnostics data (diagnostics.sel)")
        diag_url = f"{self.url}/diagnostics.sel?{querystr()}"
        diag_response = self.post(diag_url, params=self._rtac_session, dev=dev)

        # TODO: move diag parsing into separate function to clean this up
        if not diag_response or not diag_response.content:
            report_url = f"{self.url}/diag_report.sel"
            self.log.warning(f"No results from '{diag_url}', attempting '{report_url}")
            diag_response = self.post(report_url, params=self._rtac_session, dev=dev)
            # TODO: handle errors if diag_report.sel fails

        try:
            web_diag = {}
            self.dump_htmltable(diag_response, web_diag)

            # strings from lists to decimal
            if "Main Task Usage" in web_diag:
                mt_use = web_diag.pop("Main Task Usage")[1][:-1]
                web_diag["main_task_usage"] = int(mt_use) / 100.0
            if "Automation Task Usage" in web_diag:
                at_use = web_diag.pop("Automation Task Usage")[1][:-1]
                web_diag["automation_task_usage"] = int(at_use) / 100.0

            if "Power Source Voltage" in web_diag:
                web_diag["power_source_voltage"] = float(
                    web_diag.pop("Power Source Voltage")
                )

            # KB strings to int
            # (TODO: better way to do this that handles other types, e.g MB, GB)
            # use humanfriendly?
            for key in [
                "Memory Usage (RAM)",
                "Memory Available (RAM)",
                "Storage Usage",
                "Storage Available",
                "Number of Users Logged In",
            ]:
                if key in web_diag:
                    new_key = (
                        utils.clean_replace(key, "", "():").replace(" ", "_").lower()
                    )
                    web_diag[new_key] = int(str(web_diag.pop(key)).split(" ")[0])

            dash_config["web_diagnostics"] = web_diag

            if web_diag.get("memory_usage_ram"):
                dev.hardware.memory_usage = int(web_diag.pop("memory_usage_ram"))
            if web_diag.get("memory_available_ram"):
                dev.hardware.memory_available = int(
                    web_diag.pop("memory_available_ram")
                )
            if web_diag.get("storage_usage"):
                dev.hardware.storage_usage = int(web_diag.pop("storage_usage"))
            if web_diag.get("storage_available"):
                dev.hardware.storage_available = int(web_diag.pop("storage_available"))
            if web_diag.get("Current Project"):
                dev.logic.name = str(web_diag.pop("Current Project")).strip()
            if web_diag.get("Modified Time of Project"):
                try:
                    raw_ts = str(web_diag["Modified Time of Project"]).strip()
                    dev.logic.last_updated = utils.parse_date(raw_ts)
                    del web_diag[
                        "Modified Time of Project"
                    ]  # del here in case parsing fails
                except Exception as ex:
                    self.log.warning(
                        f"Failed to parse project modification timestamp: {ex}"
                    )

            dev.extra["web_diagnostics"] = dash_config["web_diagnostics"]
        except ValueError:
            self.log.exception(
                "No table in 'diagnostics' or failed to parse "
                "parts of it (check credentials?)"
            )

        # === Post summary ===
        self.log.info("Getting RTAC post summary data (post_summary.sel)")
        post_summary = self.post(
            f"{self.url}/post_summary.sel?{querystr()}",
            params=self._rtac_session,
            dev=dev,
        )

        if not post_summary or not post_summary.content:
            self.log.error("No RTAC post summary data (post_summary.sel)")
        else:
            try:
                self.dump_htmltable(post_summary, dash_config["web_post_summary"])
                dev.extra["web_post_summary"] = dash_config["web_post_summary"]
                # TODO: cleanup the default keys and values for the dicts from various pages
                #   remove ':', lowercase underscore_separated, bools
                # TODO: dump parsed intermediate representations to JSON files
                if (
                    "DDR2 SDRAM OK" in dash_config["web_post_summary"]
                    and not dev.hardware.memory_type
                ):
                    dev.hardware.memory_type = "ddr2_sdram"
            except ValueError as ex:
                self.log.debug(f"No table in 'post_summary': {ex} (check credentials?)")

        return dash_config

    def view_usagepolicy(self, dev: DeviceData) -> dict:
        """
        Get the data from the RTAC 'usagepolicy' (``customize.sel``).
        """
        self.log.info("Getting RTAC usage policy (customize.sel)")

        web_usagepolicy = {}
        usage_policy = self.post(
            f"{self.url}/customize.sel", params=self._rtac_session, dev=dev
        )
        self.dump_htmltable(usage_policy, web_usagepolicy)
        dev.extra["web_usagepolicy"] = web_usagepolicy

        return {"web_usagepolicy": web_usagepolicy}

    def view_filesondevice(self, dev: DeviceData) -> dict:
        """
        Get data about files on a RTAC (``file_repository.sel``).
        """
        self.log.info("Getting RTAC file listing (file_repository.sel)")

        # Note: we can potentially upload files via this interface using
        # upload_file.sel (params from data + contents)

        files_repo = self.post(
            f"{self.url}/file_repository.sel", params=self._rtac_session, dev=dev
        )

        raw_web_files = {}
        self.dump_htmltable(files_repo, raw_web_files)

        web_files = {}
        for filename, values in raw_web_files.items():
            if not filename:  # Skip None-types
                continue

            file_data = {
                "name": str(filename),
                "size": int(values[1]),
            }

            try:
                file_data["timestamp"] = utils.parse_date(values[0])
            except Exception as ex:
                self.log.warning(
                    f"Failed to parse web file timestamp for '{values[0]}': {ex}"
                )

            web_files[filename] = file_data
            dev.related.files.add(str(filename))

        dev.extra["web_files"] = web_files
        return {"web_files": web_files}

    def download_http_files(self, dev: DeviceData) -> dict:
        """
        Take file listing from view_filesondevice() and download from web server
        """
        # just a dict to indicate a file was downloaded from the device
        downloaded_files = {}
        if not dev.extra["web_files"]:
            self.log.error(
                "PEAT did not find any web files listed on the device, skipping file download..."
            )
            return downloaded_files

        num_downloads = len(dev.extra["web_files"])
        self.log.info(f"Attempting to download {num_downloads} file(s)...")

        # For each file in web_files, send a request to download the file to local machine
        for file in dev.extra["web_files"]:
            filename = str(file)
            self.log.info(f"Attempting to download file via http: {file}")

            payload = {
                "header": "{'User-Agent': 'Mozilla/5.0'}",
                "vfsid": "file_manager",
                "filename": filename,
                **self._rtac_session,
            }

            try:
                dl_repo = self.post(f"{self.url}/download.sel", params=payload, dev=dev)
                dev.write_file(dl_repo.content, filename)
                downloaded_files[filename] = "success"
            except AttributeError as err:
                # Attribute error is likely caused by file not being found
                self.log.error(
                    f"Error trying to download {filename} (possible incorrect filename?): {err}"
                )
                downloaded_files[filename] = "failure"

        return downloaded_files

    # TODO: view_features parsing is not extracting anything on PEAT rack rtac
    def view_features(self, dev: DeviceData) -> dict:
        """
        Get data about features on a RTAC (``licensed_features.sel``).
        """
        self.log.info("Getting RTAC features list (licensed_features.sel)")

        web_features = {}
        features = self.post(
            f"{self.url}/licensed_features.sel", params=self._rtac_session, dev=dev
        )
        self.dump_htmltable(features, web_features)

        dev.extra["web_features"] = web_features
        return {"web_features": web_features}

    def view_accounts(self, dev: DeviceData) -> dict:
        """
        Get data about user accounts on a RTAC (``user_table.sel``).
        """

        # NOTE
        #   Users can be added and passwords can be changed via this interface
        #   Add user with "add_user.sel" then "add_user_save.sel"
        #     Param(account_expiration, passwd, confirm_password, complex_password,
        #           submit=Submit, auto_login, status, user_id, submit,
        #           membership_list, description, close=Close)
        #   Change password with "change_password.sel" then "password_save.sel"
        #     Param(new_password, old_password, confirm_password)

        self.log.info("Getting RTAC user accounts (user_table.sel)")

        accounts_page = self.post(
            f"{self.url}/user_table.sel", params=self._rtac_session, dev=dev
        )

        raw_web_accounts = {}
        self.dump_htmltable(accounts_page, raw_web_accounts)

        # Dates are <Create, Last Login, Password Changed>
        # TODO: could do this with a string slice or something intelligent
        regex = (
            r"(?P<created>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"(?P<last_login>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"(?P<password_changed>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
        )
        web_accounts = {}

        for username, values in raw_web_accounts.items():
            # add username to related even if there's no values
            dev.related.user.add(username)

            if not values:
                self.log.warning(f"values is empty for username {username}")
                continue

            web_accounts[username] = {
                "status": values[0],
            }

            if len(values) < 2:
                self.log.warning(f"len(values) < 2: {values}")
                continue

            # parse out web account timestamps into fields
            match = re.match(regex, values[1], re.ASCII | re.IGNORECASE)
            if match:
                web_accounts[username].update(match.groupdict())

        # Add users to data model
        for username, values in web_accounts.items():
            user = User(
                name=username,
                extra=values,
            )

            dev.store("users", user, lookup="name")

        dev.extra["web_accounts"] = web_accounts
        return {"web_accounts": web_accounts}

    def view_user_roles(self, dev: DeviceData) -> dict:
        """
        Get data about user roles on a RTAC (``list_user_roles.sel``).
        """
        # New user roles can be added
        # add_new_user_defined_role_template.sel -> add_user_role.sel
        #   Params(role_name, role_desc, membership_list, perm_list)
        self.log.info("Getting RTAC user roles (list_user_roles.sel)")

        web_user_roles = {}
        user_roles = self.post(
            f"{self.url}/list_user_roles.sel", params=self._rtac_session, dev=dev
        )
        self.dump_htmltable(user_roles, web_user_roles)
        for role in web_user_roles.keys():
            dev.related.roles.add(role.strip())

        dev.extra["web_user_roles"] = web_user_roles
        return {"web_user_roles": web_user_roles}

    def view_syslog(self, dev: DeviceData) -> dict:
        """
        Get the system log (SOE, Sequence of Events) from a RTAC (``soe.csv``).
        """
        self.log.info("Getting RTAC system log data (soe.csv)")

        response = self.session.get(
            f"{self.url}/soe.csv",
            params=self._rtac_session,
            timeout=self.timeout + 10.0,
        )

        if not response or not response.text:
            self.log.error(
                "No response or data for Sequence of Events (SOE) log (soe.csv)"
            )

        dev.write_file(
            data=response.text,
            filename="soe.csv",
            out_dir=dev.get_sub_dir("http_files"),
        )

        # Ensure csv has contents
        # TODO: can we just read this using python's csv module?
        # TODO: move SOE file parsing into separate function
        # TODO: support parsing of SOE log file directly with SELRTAC.parse()
        # TODO: this code needs some serious cleanup and refactoring
        web_syslog_events = []
        syslog_lines = response.text.split("\n")
        if len(syslog_lines) > 0:
            labels = syslog_lines[0].split(",")
            # TODO: better error handling for parsing of each event, failure
            #   of one event's parsing shouldn't break the rest of them
            for i in range(1, len(syslog_lines)):
                # If event has no entries, skip
                if len(syslog_lines[i]) == 0:
                    continue
                raw = {}
                line = [x.strip('"') for x in syslog_lines[i].split('",') if x]
                # For each event column, fill in details, and populate event
                for col_idx in range(len(labels)):
                    trim_label = labels[col_idx][1:-1]
                    raw[trim_label] = line[col_idx]
                web_syslog_events.append(raw)

                # Process the event into the data model
                # TODO: add more log messages with status of parsing
                msg = raw["message"].lower()
                raw_msg = raw["message"].strip()

                if raw.get("tag_name"):
                    event_action = (
                        raw["tag_name"].split(".")[-1].lower().replace("_", "-")
                    )
                else:
                    event_action = utils.clean_replace(msg, "-", " ,:")
                    event_action = event_action.strip("-").replace("--", "-")

                event_category = {"host"}
                event_kind = {"event"}
                # TODO: set outcome to alarm state in some cases?
                event_outcome = ""  # "success", "failure", "unknown", ""
                event_type = {"info"}
                extra = {}

                if "user_changed_settings" in msg:
                    event_category.update({"configuration", "host"})
                    event_type.update({"change", "access", "user"})

                    match = re.match(
                        # "Time System modified settings"
                        r"^(?P<username>.*) (changed|modified) settings$",
                        # NOTE: want to make sure the username is case-sensitive
                        raw_msg,
                        flags=re.IGNORECASE,
                    )

                    if match:
                        extra["user"] = match.groupdict()["username"].strip()
                        dev.related.user.add(extra["user"])
                    else:
                        self.log.warning(
                            f"user_changed_settings: "
                            f"Failed to match username regex for message '{raw_msg}'"
                        )
                        event_kind.add("pipeline_error")
                elif "password_changed" in msg:
                    event_category.update({"configuration", "host"})
                    event_type.update({"change", "access", "user", "connection"})
                    match = re.match(
                        # "admin changed password for admin"
                        r"^(?P<username>.*) changed password for (?P<target>.*)$",
                        # NOTE: want to make sure the username is case-sensitive
                        raw_msg,
                        flags=re.IGNORECASE,
                    )

                    if match:
                        extra["acting_user"] = match.groupdict()["username"].strip()
                        extra["target_user"] = match.groupdict()["target"].strip()
                        dev.related.user.add(extra["acting_user"])
                        dev.related.user.add(extra["target_user"])
                    else:
                        self.log.warning(
                            f"password_changed: "
                            f"Failed to match username regex for message '{raw_msg}'"
                        )
                        event_kind.add("pipeline_error")
                elif "change" in msg:
                    event_category.update({"configuration", "host"})
                    event_type.add("change")
                elif "power" in msg and "up" in msg:
                    event_type.add("start")
                elif "archive cleared" in msg:
                    event_category.add("database")
                    event_type.update({"change", "deletion"})
                elif "factory reset" in msg:
                    event_category.update({"configuration", "host"})
                    event_type.add("change")
                elif (
                    "attempt failed" in msg
                    or "login attempt from" in msg
                    or "unauthorized" in msg
                    or "unsuccessful_log_on_attempt" in msg
                ):
                    event_category.update({"authentication", "network", "session"})
                    event_type.update({"access", "connection", "denied", "user"})
                    event_outcome = "failure"
                    if "login attempt" in msg:
                        event_action = "login-attempt"
                        match = re.match(
                            # "admin login attempt failed"
                            # "Unknown login attempt from 192.168.1.1 failed"
                            r"^(?P<username>.*) login attempt (from (?P<host>[:\.\w]+) )?failed.*",
                            # NOTE: want to make sure the username is case-sensitive
                            raw_msg,
                            flags=re.IGNORECASE,
                        )

                        if match:
                            extra["user"] = match.groupdict()["username"].strip()
                            dev.related.user.add(extra["user"])

                            host = match.groupdict().get("host")
                            if (
                                host
                                and utils.is_ip(host)
                                and not (":" in host and host.count(".") == 3)
                            ):
                                dev.related.ip.add(host)
                            elif host:
                                dev.related.hosts.add(host)
                        else:
                            self.log.warning(
                                f"login_attempt: "
                                f"Failed to match username regex for message '{raw_msg}'"
                            )
                            event_kind.add("pipeline_error")
                elif "logged o" in msg or "login" in msg or "log_On" in msg:
                    event_category.update({"authentication", "network", "session"})
                    event_type.update({"access", "allowed", "connection", "user"})
                    event_outcome = "success"

                    # "<User> logged off device via Web"
                    # "<User> logged on device via ODBC"
                    match = re.match(
                        r"^(?P<username>.*) logged (?P<direction>off|on) "
                        r"device via (?P<service>.*)$",
                        # NOTE: want to make sure the username is case-sensitive
                        raw_msg,
                    )

                    if match:
                        extra["logon_user"] = match.groupdict()["username"].strip()
                        dev.related.user.add(extra["logon_user"])
                        extra["logon_service"] = (
                            match.groupdict()["service"].strip().lower()
                        )
                        if extra["logon_service"] in ["odbc", "web"]:
                            event_category.add("database")
                        event_action = (
                            f"user-logged-{match.groupdict()['direction']}"
                            f"-via-{extra['logon_service']}"
                        )
                    else:
                        self.log.warning(
                            f"logged_on: "
                            f"Failed to match username regex for message '{raw_msg}'"
                        )
                        event_kind.add("pipeline_error")
                elif "application_status" in msg:
                    # "The rtacsnmpmgr application has been restarted"
                    # TODO: extract application name and put in metadata
                    event_category.update({"process", "host"})
                    event_outcome = "unknown"
                    event_type.add("change")
                    if "restarted" in msg:
                        event_action = "application-restarted"
                elif (
                    "firmware: " in msg
                    or "project: " in msg
                    or "power_up_description" in msg
                ):
                    event_kind.add("state")
                    event_action = "rtac-started"
                    # TODO: using a regex here would be more flexible to format changes
                    if "project: " in msg:
                        project_name = msg.split("project: ")[-1].strip()
                        extra["project_name"] = project_name
                        if not dev.logic.name:
                            dev.logic.name = project_name
                    if "firmware: " in msg:
                        extra["firmware"] = (
                            msg.split(",")[0].split("firmware: ")[-1].strip()
                        )
                        process_fid(extra["firmware"], dev)

                # TODO: change time parsing if 't_dst_enabled' is 't' instead of 'f'?
                #   In other words, if daylight savings time is enabled on device
                # t_value: when event actually occurred
                # this value can sometimes be 'f' for some reason
                created_ts = None
                t_value = raw.get("t_value", "").strip()
                if t_value and len(t_value) > 1:
                    created_ts = utils.parse_date(t_value)
                # TODO: add a 3rd timestamp to Event data model for this thing
                #   creation_timestamp: when log was last generated
                #       on RTAC (recovered/rebuilt?)
                ingest_ts = None
                ct = raw.get("creation_timestamp", "").strip()
                if ct and len(ct) > 1:
                    ingest_ts = utils.parse_date(ct)
                if ingest_ts:
                    extra["creation_timestamp"] = ingest_ts

                for key in [
                    "category",
                    "priority",
                    "tag_name",
                    "host_name",
                    "device_name",
                    "device_guid",
                    "comment",
                    "ack_operator_username",
                ]:
                    val = raw.get(key, "").strip()
                    if val:
                        if val.lower() == "f":
                            extra[key] = False
                        elif val.lower() == "t":
                            extra[key] = True
                        else:
                            extra[key] = val
                if "device_name" in extra:
                    dev.related.hosts.add(extra["device_name"])
                if "host_name" in extra:
                    dev.related.hosts.add(extra["host_name"])

                event = Event(
                    action=event_action,
                    category=event_category,
                    created=created_ts,
                    dataset="web_syslog",
                    kind=event_kind,
                    message=raw["message"].strip(),
                    extra=extra,
                    module="SELRTAC" if not dev._module else dev._module.__name__,
                    original=syslog_lines[i],
                    outcome=event_outcome,
                    provider=dev.name if dev.name else dev.get_id(),
                    sequence=int(i),
                    type=event_type,
                )
                # If a event exists with the same timestamp, update it.
                # Otherwise, it's a new event and don't bother comparing values.
                dev.store("event", event)

        dev.write_file(web_syslog_events, "raw-web-syslog-events.json")

        return {"web_syslog_events": web_syslog_events}

    def view_ip_tables(self, dev: DeviceData) -> dict:
        """
        View diagnostics and network data from a RTAC (``services_rpt.cev``).

        Data includes: network state, firewall, route table,
            exeguard, prp diagnostic, arp table.
        """
        self.log.info("Getting RTAC network info (services_rpt.cev)")
        ip_settings = self.post(
            f"{self.url}/services_rpt.cev", params=self._rtac_session, dev=dev
        )

        if not ip_settings or not ip_settings.text:
            self.log.warning(
                "No content returned for services_rpt.cev (web_ip_settings)"
            )
            return {"web_ip_settings": {}}

        # TODO: finish implementing
        # TODO: dev.related.ip.add(...)
        web_ip_settings = {}
        self.log.debug(f"ip_settings content: {ip_settings.text}")

        dev.extra["web_ip_settings"] = web_ip_settings
        return {"web_ip_settings": web_ip_settings}

    def view_ldap(self, dev: DeviceData) -> dict:
        """
        Get LDAP data from a RTAC (``ldap_server_table.sel``).
        """
        # NOTE: upload with "upload_file.sel" (params form data+contents)
        config = {
            "web_ldap": {
                "servers": {},
                "ldap_setting": {},
                "ldap_group_mapping": {},
                "ldap_attribute_mapping": {},
            }
        }

        self.log.info("Getting RTAC LDAP data")

        ldap_server = self.post(
            f"{self.url}/ldap_server_table.sel", params=self._rtac_session, dev=dev
        )
        try:
            self.dump_htmltable(ldap_server, config["web_ldap"]["servers"])
            # TODO: dev.related.user.add(...)
            dev.extra["web_ldap_accounts"] = config["web_ldap"]["servers"]
        except ValueError:
            self.log.exception("not table in servers")

        ldap_settings = self.post(
            f"{self.url}/ldap_settings_table.sel", params=self._rtac_session, dev=dev
        )
        try:
            self.dump_htmltable(ldap_settings, config["web_ldap"]["ldap_setting"])
            dev.extra["web_ldap_setting"] = config["web_ldap"]["ldap_setting"]
        except ValueError:
            self.log.exception("not table in general settings")

        ldap_groups = self.post(
            f"{self.url}/ldap_group_mapping_table.sel",
            params=self._rtac_session,
            dev=dev,
        )
        try:
            self.dump_htmltable(ldap_groups, config["web_ldap"]["ldap_group_mapping"])
            dev.extra["web_ldap_grpmapping"] = config["web_ldap"]["ldap_group_mapping"]
        except ValueError:
            self.log.exception("not table in group mapping")

        ldap_attributes = self.post(
            f"{self.url}/ldap_attribute_mapping_table.sel",
            params=self._rtac_session,
            dev=dev,
        )
        try:
            self.dump_htmltable(
                ldap_attributes, config["web_ldap"]["ldap_attribute_mapping"]
            )
            dev.extra["web_ldap_attmapping"] = config["web_ldap"][
                "ldap_attribute_mapping"
            ]
        except ValueError:
            self.log.exception("not table in attribute mapping")

        return config

    # -------------------- RTAC COMMANDS --------------------

    def rtac_delete_logs(self) -> None:
        """
        Clear log data from a RTAC (``system_restore.sel``).
        """
        self.log.warning("Deleting logs from RTAC")
        session_data = {
            "restore": "false",
            "complete": "true",
            **self._rtac_session,
        }
        self.post(f"{self.url}/system_restore.sel", params=session_data)

    def rtac_log_out(self) -> None:
        """
        Log out of the RTAC (``logout.sel``).
        """
        if self.rtac_logged_in:
            self.log.info("Logging out from RTAC")
            session_data = {
                "action": "logoff",
                **self._rtac_session,
            }
            self.post(f"{self.url}/logout.sel", params=session_data)
            self.rtac_logged_in = False

    def rtac_reboot(self) -> None:
        """
        Restart RTAC (``reboot_device.cev``).
        """
        self.log.info("Rebooting RTAC")
        self.post(f"{self.url}/reboot_device.cev", params=self._rtac_session)
        self.rtac_logged_in = False

    # -------------------- Relay Web pages --------------------

    # TODO: split parsing of page results into separate methods
    #   e.g: parse_device_features() that gets called by get_device_features()
    # TODO: unit tests of parsing methods

    # NOTE: get_device_features() needs to be called before other methods for
    #   some reason, need to get to the bottom of why this is.

    def get_device_features(self, dev: DeviceData) -> bool:
        """
        Get basic information about a relay.

        ``ver`` command page.

        Data

        - Device model
        - FID
        - BFID
        - CID
        - Checksum (firmware)
        - Firmware info
        - Part number
        - Serial number
        - Various additional information about capabilities and boards
        """
        try:
            page = self.read_page("ver")
        except Exception as ex:
            self.log.warning(f"Failed to read device features page: {ex}")
            return False

        process_info_into_dev(
            {
                "FID": parse_simple_line("FID", page),
                "BFID": parse_simple_line("BFID", page),
            },
            dev,
        )

        # 451  : "Checksum:    <checksum>"
        # 351S : "checksum <checksum>"
        checksum_res = re.findall(r"hecksum[:]?\s*(\S+)\s*(?:OK)?\n", page)
        if checksum_res:
            checksum = checksum_res[0].strip()
            dev.firmware.checksum = checksum
            # This may or may not be an actual hash, and in some
            # cases it's definitely not, e.g. "B0AB".
            try:
                checksum_hash = validate_hash(checksum)
                dev.related.hash.add(checksum_hash)
                if not dev.firmware.hash.md5 and len(checksum) == 32:
                    dev.firmware.hash.md5 = checksum_hash
            except ValueError:
                pass

        # Serial number
        if "Serial Number" in page:
            dev.serial_number = parse_simple_line("Serial Number", page)

        # NOTE: 351S doesn't have CID on ver page
        if "CID" in page:
            dev.extra["CID"] = parse_simple_line("CID", page)

        # 351S is "Partnumber"
        dev.part_number = parse_simple_line(
            "Partnumber" if "Partnumber" in page else "Part Number", page
        )

        # TODO: separate 451/351S specific information into sub-structures?
        # Data present on the 451 page
        if "Mainboard" in page:
            dev.extra["mainboard"] = parse_simple_table("Mainboard", "Front", page)

        if dev.extra.get("mainboard"):
            # memory_available
            if dev.extra["mainboard"].get("RAM Size") and not dev.hardware.memory_total:
                try:
                    dev.hardware.memory_total = humanfriendly.parse_size(
                        dev.extra["mainboard"]["RAM Size"], binary=True
                    )
                    if not dev.hardware.memory_type:
                        dev.hardware.memory_type = "ram"
                except Exception as ex:
                    self.log.error(f"Failed to parse RAM size: {ex}")

        if "Front Panel" in page:
            dev.extra["front_panel"] = parse_simple_line("Front Panel", page)

        # TODO: structure of page is totally different on 311L,
        # need to make more robust parsers
        # Text for start of tables is the same, and they're indented
        # (2 spaces on 311L, 4 spaces on 451)
        # Maybe a regex?
        #   parse section by section using regex for various formats
        #   on 451, selboot is a table
        if "Extended Relay Features" in page:
            dev.extra["extended_relay_features"] = parse_simple_list(
                "Extended Relay Features", "If the above", page
            )

        if "E4 Configuration" in page:
            dev.extra["e4_configuration"] = parse_simple_line("E4 Configuration", page)

        if "Interface Boards" in page:
            dev.extra["interface_boards"] = parse_simple_table(
                "Interface Boards", "E4", page
            )

        if "Analog Inputs" in page:
            dev.extra["analog_inputs"] = parse_simple_table(
                "Analog Inputs",
                "Interface Boards",
                # Device on the MOSAICS rack had this text,
                # while the one on the PEAT rack did not.
                page.replace(" (provided by remote Axion Nodes)", ""),
            )

        # Data present on the 351/351S page
        # 451 has "Extended Relay Features" so use a newline to differentiate
        if "\nRelay Features" in page:
            dev.extra["relay_features"] = parse_simple_list(
                "Relay Features", "SELboot", page
            )

        # TODO: 351/351S Analog Input Voltage
        #   Analog Input Voltage (PT):  300 Vac, Wye, Delta, or Single connected
        # TODO: 351/351S Analog Input Current
        #   Analog Input Current (CT):  1 Amp Phase, 1 Amp Neutral
        # TODO: 351/351S Main Board I/O
        #   Main Board I/O:  2 High I/C Outputs, 6 Standard Outputs, 6 Inputs
        # TODO: 351S Additional I/O
        #   Additional I/O:  4 Standard Outputs, 16 Inputs

        return True

    def get_status(self, dev: DeviceData) -> bool:
        """
        Get device status information from a relay.

        Returns:
            Data extracted from the status page.
            Refer to :func:`~peat.modules.sel.relay_parse.parse_status_output`
            for details on the data extracted from this page.
        """
        try:
            page = self.read_page("sta")
        except Exception as ex:
            self.log.warning(f"Failed to get status page: {ex}")
            return False
        return self._process_status_data(split_lines(page), dev)

    def get_communications(self, dev: DeviceData) -> bool:
        """
        Get communication interface status and current state from a relay.

        NOTE: this is not available on 351S or 351.
        """
        try:
            page = self.read_page("eth")
        except Exception:
            self.log.warning("Failed to get communications page ('eth')")
            return False

        # Extract info about the communication ports
        extracted_ports = re.findall(
            r"\nPORT\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", page
        )
        port_information = {
            str(port[0]): {  # Key is the port name
                "link": str(port[1]).lower(),
                "speed": str(port[2]).replace("---", ""),
                "duplex": str(port[3]).replace("---", ""),
                "media": port[4],
            }
            for port in extracted_ports
        }

        # Extract MAC addresses (451 in PEAT rack has "MAC 1" and "MAC 2")
        extracted_macs = re.findall(r"\nMAC(?::| \d:)\s(\S+)", page)
        # Use a set to ensure there are no duplicates, then convert to list
        macs = list({m.lower().replace("-", ":") for m in extracted_macs})

        # Extract Ethernet statistics
        # NOTE: if counters exceed a certain value, then the values will be
        # replaced with "$$$$" characters. What this value is exactly is
        # unknown and doesn't appear to be referenced in SEL's documentation.
        # This behavior will likely vary by relay model and firmware revision.
        # Simple fix is to reset the counters with "eth c" command on the relay.
        # Example output below:
        #      PACKETS                 BYTES               ERRORS
        #    SENT     RCVD         SENT       RCVD      SENT    RCVD
        # $$$$$$$  $$$$$$$   1463657022 1664082074         0       0
        extracted_stats = re.findall(
            r"\n\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)",
            page,
        )

        if extracted_stats:
            stats = extracted_stats[0]
            network_statistics = {
                "packets_sent": int(stats[0]) if "$" not in stats[0] else -1,
                "packets_received": int(stats[1]) if "$" not in stats[1] else -1,
                "bytes_sent": int(stats[2]) if "$" not in stats[2] else -1,
                "bytes_received": int(stats[3]) if "$" not in stats[3] else -1,
                "errors_sent": int(stats[4]) if "$" not in stats[4] else -1,
                "errors_received": int(stats[5]) if "$" not in stats[5] else -1,
            }
        else:
            self.log.warning(
                "Failed to extract network statistics from ETH page (no regex match)"
            )
            network_statistics = {}

        # Extract IPv4 address and subnet information
        extracted_addr = parse_simple_line("IP ADDRESS", page)
        if "/" in extracted_addr:
            addr, mask = split_ipv4_cidr(extracted_addr)
        else:
            # TODO: 351 probably stores subnet mask as separate value
            addr = extracted_addr
            mask = ""

        communications = {
            "mac_addresses": macs,
            "ipv4_address": addr,
            "ipv4_subnet_mask": mask,
            "gateway": parse_simple_line("DEFAULT GATEWAY", page),
            "network_mode": parse_simple_line("NETMODE", page),
            "primary_port": parse_simple_line("PRIMARY PORT", page),
            "active_port": parse_simple_line("ACTIVE PORT", page),
            "port_information": port_information,
            "statistics": network_statistics,
        }

        # TODO: add data to the appropriate Interface in data model
        dev.extra["communications"] = communications

        return True

    def get_port_settings(self, dev: DeviceData) -> bool:
        """
        Get communication port settings from a relay.
        """
        # Simple device model-agnostic check to determine the proper URL format
        p1_page = ""  # Cache the page from our silly check
        if not self._port_args_len:
            # %20 = space character (" "). So, "sho" with "P 1" as parameter for 451.
            for args in [("shop1",), ("sho", "P%201")]:
                try:
                    p1_page = self.read_page(*args)
                except Exception:
                    continue
                else:
                    self._port_args_len = len(args)
                    break

        if not self._port_args_len:
            self.log.warning("Unable to find a valid port settings page")
            return False

        port_results = {}
        for index in range(1, 6):
            # "Port F" is sometimes referred to as port 4 in the relay...
            if index == 4:
                port_id = "F"
            else:
                port_id = str(index)
            port_name = f"Port {port_id}"

            if index == 1 and p1_page:
                page = p1_page
            else:
                try:
                    if self._port_args_len == 1:  # 351, 351S
                        # Port F is retrieved as port 4 on older devices
                        page = self.read_page(
                            f"shop{str(4) if index == 4 else port_id}"
                        )
                    else:  # 451
                        page = self.read_page("sho", f"P%20{port_id}")
                except Exception as ex:
                    self.log.warning(f"Failed to get {port_name} page: {ex}")
                    continue

            if "Invalid Command" in page:
                self.log.debug(f"Device doesn't have {port_name} ('Invalid Command')")
                port_results[port_name] = {}

            # SEL 351, 351S, 311L
            elif self._port_args_len == 1:
                raw = re.sub("Port .", "", page, count=1, flags=re.ASCII)
                raw = re.sub("= *", "=", raw, flags=re.ASCII)
                raw = " ".join(raw.split()).replace(" =", "=")

                pairs = [x.split("=") for x in raw.split(" ") if "=" in x]
                raw_settings = {x[0]: x[1] for x in pairs}
                port_results[port_name] = raw_settings

                process_port_settings(port_id, raw_settings, dev)

            # SEL 451
            else:
                raw_settings = parse_multiple_lists(page)
                port_results[port_name] = raw_settings

                # TODO: this is a hack and we may be losing some information
                flat_settings = {}
                for val in raw_settings.values():
                    flat_settings.update(val)

                process_port_settings(port_id, flat_settings, dev)

        dev.extra["interfaces"] = port_results
        return True

    def get_front_panel_settings(self, dev: DeviceData) -> bool:
        """
        Get front panel settings from a relay.
        """
        try:
            page = self.read_page("sho", "F")
        except Exception as ex:
            self.log.warning(f"Failed to get front panel settings page: {ex}")
            return False

        settings = normalize_keys(parse_multiple_lists(page))
        settings["front_panel_settings"] = parse_comments(
            settings["front_panel_settings"]
        )

        dev.extra["front_panel_data"] = settings
        return True

    def get_sequential_events(self, dev: DeviceData) -> bool:
        """
        Get Sequential Event Recorder (SER) log data from a relay.

        This method has been tested against SEL 351, 351S, and 451 relays.
        """
        try:
            page = self.read_page("ser")
        except Exception as ex:
            self.log.warning(f"Failed to read SER page: {ex}")
            return False

        try:
            parse_and_process_events(page, "Sequential Event Recorder ('ser')", dev)
        except Exception:
            self.log.exception(f"Failed parsing of SER data from {dev.ip}")
            return False

        return True

    # TODO: separate parsing
    # TODO: generalize for use with Telnet/Serial => relay_parse.parse_history
    def get_historical_events(self, dev: DeviceData) -> bool:
        """
        Get historical event log from a relay.

        Tested on SEL 351S and 451 relays. May work on the 351.

        .. warning::
           Older versions of the 351 may not support this (failed on a device
           with copyright year 2009, your mileage may vary on newer devices).
        """
        try:
            page = self.read_page("his")
        except Exception as ex:
            self.log.warning(f"Failed to read historical events page: {ex}")
            return False

        if "No data available" in page:  # SEL 451
            self.log.debug("No historical events available")
            return False

        lines = split_lines(page)
        # Find the header line for the actual events
        header_index = next(
            i for i, s in enumerate(lines) if s[0] == "#" and "date" in s.lower()
        )
        if header_index != 0:
            # Process the status information front matter
            self._process_status_data(lines[:header_index], dev)

        if "History Buffer Empty" in page:  # SEL 351S (and possibly the 351?)
            self.log.warning("Historical event buffer empty")
            return False

        for raw_line in lines[header_index + 1 :]:
            # TODO: handle links in lines
            line = raw_line.strip()
            hist_event_regex = (
                r"(\d*)[ ]*(\d{2}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3}) "
                r"([a-zA-Z ]*)[ ]*(-?\d*\.\d*|\$*)[ ]*(\d*) "
                r"(\d*\.\d*)[ ]*(\d)[ ]*(\d)[ ]*(\d*)?"
            )
            res = re.match(hist_event_regex, line, re.ASCII | re.IGNORECASE)
            if not res:
                self.log.warning(
                    f"Historical Event line parsing regex failed"
                    f"\n***Raw Data: {repr(line)}"
                )
                continue
            values = res.groups()

            event_val = values[3].strip()

            # Store the actual fields as named by SEL in the event metadata
            # for easier reference without looking at "original".
            extra = {
                "event": event_val,
                "current": float(values[5].strip()),
                "frequency": float(values[6].strip()),
                "group": int(values[7].strip()),
                "shot": int(values[8].strip()),
            }

            if "$" not in values[4]:
                # Represent "$$$$$$$" values by not including locat field
                extra["locat"] = float(values[4].strip())

            if values[9]:
                extra["targets"] = int(values[9].strip())

            event = Event(
                action=event_val,
                category={"host"},
                created=date_parse(f"{values[1]} {values[2]}"),
                dataset="Historical Events ('his')",
                kind={"event"},
                original=raw_line,
                provider=self.ip,
                # TODO: should sequence be reverse order, since "1" in the
                #  log is actually the newest event, not the oldest?
                sequence=int(values[0]),
                type={"info", "change"},
                extra=extra,
            )

            dev.store("event", event)

        return True

    def get_meter_automation(self, dev: DeviceData) -> bool:
        """
        Get meter automation data from a relay.

        Values: :class:`dict` of ``{"AMV<int>": <float>}``
        """
        try:
            page = self.read_page("met", "AMV")
        except Exception as ex:
            self.log.warning(f"Failed to get meter automation page: {ex}")
            return False

        values = re.findall(r"(AMV\d*)\s=\s+(\S+)", page)

        dev.extra["meter_automation"] = {v[0]: float(v[1]) for v in values}
        return True

    def get_meter_protection(self, dev: DeviceData) -> bool:
        """
        Get meter protection data from a relay.

        Values: :class:`dict` of ``{"PMV<int>": <float>}``
        """
        try:
            page = self.read_page("met", "PMV")
        except Exception as ex:
            self.log.warning(f"Failed to get meter protection page: {ex}")
            return False

        values = re.findall(r"(PMV\d*)\s=\s+(\S+)", page)

        dev.extra["meter_protection"] = {v[0]: float(v[1]) for v in values}
        return True

    def get_meter_energy(self, dev: DeviceData) -> bool:
        """
        Get meter energy data from a relay.
        """
        # TODO: more flexible way to check this instead of the model
        args = ["met", "E"] if "451" in dev.description.model else ["mete"]
        try:
            page = self.read_page(*args)
        except Exception as ex:
            self.log.warning(f"Failed to get meter energy page: {ex}")
            return False

        page = page.strip().replace("\n\n", "\n")
        values = [re.split(r"\s{3,}", line) for line in page.split("\n") if line]
        meter_energy = {}

        # 351/351S: "LAST RESET 04/10/19 14:56:09.206"
        # 451: "LAST ENERGY RESET: <timestamp>"
        if isinstance(values[-1][0], str) and "reset" in values[-1][0].lower():
            reset_ts_res = re.search(
                r"(\d+/\d+/\d+ \d+:\d+:\d+\.\d+)",
                values[-1][0],
                re.ASCII | re.IGNORECASE,
            )
            if reset_ts_res and reset_ts_res.groups():
                reset_ts = utils.parse_date(reset_ts_res.groups()[0])
                if reset_ts:
                    reset_ts = reset_ts.isoformat()
                meter_energy["last_energy_reset"] = reset_ts
            else:
                self.log.debug("Failed to parse last_energy_reset")

        # TODO: make energy parsing work for 351/351S (only works for 451 currently)
        try:
            for x in range(1, len(values[0]) - 1):
                meter_energy[values[0][x]] = {
                    "in": float(values[1][x]),
                    "out": float(values[2][x]),
                    "total": float(values[3][x]),
                }
        except IndexError as ex:
            self.log.debug(f"Failed to parse meter energy values: {ex}")

        dev.extra["meter_energy"] = meter_energy
        return True

    def get_output_data(self, dev: DeviceData) -> bool:
        """
        Get output data (main_board, etc.) from a relay.

        NOTE: this doesn't work on SEL-351 or 351S (or possibly just older software).
        """
        try:
            page = self.read_page("sho", "O")
        except Exception as ex:
            self.log.warning(f"Failed to get output data page: {ex}")
            return False

        results = normalize_keys(parse_multiple_lists(page))
        if "main_board" in results:
            results["main_board"] = parse_comments(results["main_board"])

        dev.extra["output_data"] = results
        return True

    # TODO: this isn't getting called anywhere at the moment.
    # Still needs a lot of work.
    def get_logic_data(self, dev: DeviceData) -> bool:
        """
        Get logic settings and control equations from a relay.

        This is the output of the "sho l" command, e.g. "sho l",
        "sho l 1" (logic group 1), etc.
        "sho l" (no argument) shows the logic for the "active" logic group.

        There should be 6 logic groups. Other relays may have more or less.

        This should work on 351S.

        The 451 calls this "Protection", and structure is far more complicated.
        """

        # 351S: "shol1.html", "shol2.html", etc.
        # TODO: implement for 351.
        #   "sho1.html" which shows "SHO 1" and "SHO L 1"
        #   in two separate sections in the returned page.
        # TODO: implement SEL-451 Group and Protection logic parsing.

        # Simple device model-agnostic check to determine the proper URL format
        l1_page = ""  # Cache the page from our silly check
        if not self._logic_page_style:
            # %20 = space character (" "). So, "sho" with "P 1" as parameter for 451.
            for style, args in {
                "351S": ("shol",),
                "351": ("sho1",),  # the number 1, not a 'l'
                "451": ("sho", "L%201"),
            }.items():
                try:
                    l1_page = self.read_page(*args)
                except Exception:
                    continue
                else:
                    self._logic_page_style = style
                    break

        if not self._logic_page_style:
            self.log.warning("Unable to find a valid logic settings page")
            return False

        logic_results = {}
        for index in range(1, 7):  # 1-6
            sleep(0.2)

            if index == 1 and l1_page:
                page = l1_page
            else:
                try:
                    if self._logic_page_style == "351S":
                        page = self.read_page(f"shol{index}")
                    elif self._logic_page_style == "351":
                        page = self.read_page(f"sho{index}")
                    else:  # 451
                        page = self.read_page("sho", f"L%20{index}")
                except Exception as ex:
                    self.log.warning(f"Failed to get logic group {index} page: {ex}")
                    continue

            page = page.strip()
            raw_group_str = f"raw_logic_group_{index}"
            group_str = f"group_{index}"

            dev.write_file(
                data=page,
                filename=f"{raw_group_str}.txt",
                out_dir=dev.get_out_dir() / "http_commands",
            )

            if "invalid command" in page.lower():
                self.log.debug(
                    f"Device doesn't have logic group {index} ('Invalid Command')"
                )
                logic_results[group_str] = {}

            # TODO: 351
            # SEL 351S
            elif self._logic_page_style == "351S":
                try:
                    raw_settings = {}
                    for line in page.splitlines():
                        if "=" not in line:
                            continue

                        parts = line.strip().partition("=")
                        raw_settings[parts[0].strip()] = parts[2].strip()

                    logic_results[group_str] = raw_settings
                except Exception as ex:
                    self.log.warning(f"Failed to parse 351S-style logic page: {ex}")
                    logic_results[raw_group_str] = page

            # TODO: implement 351, there are two "pre" tagged pages
            elif self._logic_page_style == "351":
                raw_settings = parse_multiple_lists(page)
                if not raw_settings:
                    logic_results[raw_group_str] = page
                else:
                    logic_results[group_str] = raw_settings

            # TODO: implement 451
            elif self._logic_page_style == "451":
                raw_settings = parse_multiple_lists(page)
                if not raw_settings:
                    logic_results[raw_group_str] = page
                else:
                    logic_results[group_str] = raw_settings
            else:
                raise PeatError(f"Unknown logic_page_style: {self._logic_page_style}")

        dev.extra["control_equations"] = logic_results
        return True

    def _process_status_data(self, lines: list[str], dev: DeviceData) -> bool:
        try:
            info = parse_status_output(lines)
            if not info:
                self.log.warning(f"Failed to parse status info\nRaw lines: {lines}")
                return False
            process_info_into_dev(info, dev)
        except Exception:
            log.exception("Failed to parse status data")
            return False
        return True

    # -------------------- Gateway Web pages --------------------

    def login_3620(
        self,
        user: str = "admin",
        passwd: str = "Admin123!",
    ) -> bool:
        """
        Login to the HTTPS web interface for the SEL-3620 Gateway.
        """
        page = self.get("", protocol="https")
        if not page:
            self.log.warning("Login failed: could not retrieve login page.")
            return False

        soup = self.gen_soup(page.content)

        input_element = soup.find("input", type="hidden")
        if not input_element:
            self.log.debug("Failed to find 'input' field in login page.")
            self.log.trace2(f"** Page data **\n{page.content}\n")
            return False

        self._rando = str(input_element.get("value"))
        SELSESSID = self._rando
        self.protocol = "https"  # Set protocol after confirming it worked

        login_data = {
            "Username": user,
            "Password": passwd,
            "submit": "Submit",
            "SELSESSID": SELSESSID,
        }

        self.cookies = {
            "Cookie": f"SELSESSID={SELSESSID}",
        }
        url = urljoin(self.url, "Login.sel")
        resp = self.post(url, data=login_data)
        if not resp or resp.status_code != 200:
            self.log.warning("Login failed: received non-200 response.")
            return False

        if "ERROR MESSAGES" in resp.text:
            return False

        self.gateway_l1_user = user
        self.session_id = resp.text
        self.gateway_logged_in = True
        self.log.info("Logged in to Gateway!")
        return True

    # TODO: generate backup
    #   FileManagement.sel#backupFileTab

    def gateway_accounts(self, dev: DeviceData) -> dict:
        """
        Get user accounts from gateway (``Users.sel``).
        """

        self.log.info("Getting gateway user accounts")
        url = urljoin(self.url, "Users.sel")
        accounts_page = self.post(url, data=self._rando, dev=dev)

        raw_web_accounts = {}
        self.dump_htmltable(accounts_page, raw_web_accounts)

        # TODO: more customization for fields, could do this
        # with a string slice or something intelligent.
        regex = (
            r"(?P<created>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"(?P<last_login>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"(?P<password_changed>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
        )
        web_accounts = {}

        for username, values in raw_web_accounts.items():
            # add username to related even if there's no values
            dev.related.user.add(username)

            if not values:
                self.log.warning(f"values is empty for username {username}")
                continue

            web_accounts[username] = {
                "status": values[0],
            }

            if len(values) < 2:
                self.log.warning(f"len(values) < 2: {values}")
                continue

            # parse out web account timestamps into fields
            match = re.match(regex, values[1], re.ASCII | re.IGNORECASE)
            if match:
                web_accounts[username].update(match.groupdict())

        # Add users to data model
        for username, values in web_accounts.items():
            user = User(
                name=username,
                extra=values,
            )

            dev.store("users", user, lookup="name")

        dev.extra["web_accounts"] = web_accounts
        return {"web_accounts": web_accounts}

    def gateway_ldap(self, dev: DeviceData) -> dict:
        """
        Get LDAP settings (``LDAP.sel``).
        """
        self.log.info("Getting LDAP settings...")
        url = urljoin(self.url, "LDAP.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()  # Raise an error for bad responses
        except Exception as ex:
            self.log.warning(f"Failed to read LDAP page: {ex}")
            return {}

        ldap_data = {}

        # TODO: parse LDAP data and put into data model
        # self.dump_htmltable(response, ldap_data)

        dev.extra["ldap"] = ldap_data
        return {"ldap_data": ldap_data}

    def gateway_radius(self, dev: DeviceData) -> dict:
        """
        Get RADIUS settings (``RADIUS.sel``).
        """
        self.log.info("Getting radius settings...")
        url = urljoin(self.url, "RADIUS.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read RADIUS settings page: {ex}")
            return {}

        radius_settings = {}

        # TODO: parse RADIUS settings and put into data model
        # self.dump_htmltable(response, radius_settings)

        dev.extra["radius_settings"] = radius_settings
        return {"radius_settings": radius_settings}

    def gateway_local_groups(self, dev: DeviceData) -> dict:
        """
        Get local groups (``LocalGroups.sel``).
        """
        self.log.info("Getting local group configuration...")
        url = urljoin(self.url, "LocalGroups.sel")
        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read local groups page: {ex}")
            return {}

        local_groups = {}

        # TODO: parse groups from page and put into data model
        # self.dump_htmltable(response, local_groups)

        dev.extra["local_groups"] = local_groups
        return {"local_groups": local_groups}

    def gateway_network_settings(self, dev: DeviceData) -> dict:
        """
        Get network settings (``NetworkSettings.sel``).
        """
        self.log.info("Getting network settings...")
        url = urljoin(self.url, "NetworkSettings.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read network settings page: {ex}")
            return {}

        gateway_network_settings = {}

        # TODO: parse network settings data and put into data model
        # self.dump_htmltable(response, gateway_network_settings)

        dev.extra["gateway_network_settings"] = gateway_network_settings
        return {"gateway_network_settings": gateway_network_settings}

    def gateway_static_routes(self, dev: DeviceData) -> dict:
        """
        Get static route configuration (``StaticRoutes.sel``).
        """
        self.log.info("Getting static route configuration...")
        url = urljoin(self.url, "StaticRoutes.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read static routes page: {ex}")
            return {}

        static_routes = {}

        # TODO: parse routes and put into data model
        # self.dump_htmltable(response, static_routes)

        dev.extra["static_routes"] = static_routes
        return {"static_routes": static_routes}

    def gateway_firewall(self, dev: DeviceData) -> dict:
        """
        Get firewall settings (``Firewall.sel``).
        """
        self.log.info("Getting host configuration...")
        url = urljoin(self.url, "Firewall.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read firewall page: {ex}")
            return {}

        firewall_settings = {}

        # TODO: parse firewall settings and put into data model
        # self.dump_htmltable(response, firewall_settings)

        dev.extra["firewall_settings"] = firewall_settings
        return {"firewall_settings": firewall_settings}

    def gateway_nat(self, dev: DeviceData) -> dict:
        """
        Get NAT settings (``NAT.sel``).
        """
        self.log.info("Getting host configuration...")
        url = urljoin(self.url, "NAT.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read NAT page: {ex}")
            return {}

        nat_settings = {}

        # TODO: parse NAT settings and put into data model
        # self.dump_htmltable(response, nat_settings)

        dev.extra["nat_settings"] = nat_settings
        return {"nat_settings": nat_settings}

    def gateway_hosts(self, dev: DeviceData) -> dict:
        """
        Get host configuration (``Hosts.sel``).
        """
        self.log.info("Getting host configuration...")
        url = urljoin(self.url, "Hosts.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read Hosts page: {ex}")
            return {}

        gateway_hosts = {}

        # TODO: parse hosts data and put into data model
        # self.dump_htmltable(response, gateway_hosts)

        dev.extra["gateway_hosts"] = gateway_hosts
        return {"gateway_hosts": gateway_hosts}

    def gateway_snmp(self, dev: DeviceData) -> dict:
        """
        Get SNMP settings (``SNMP.sel``).
        """
        self.log.info("Getting SNMP settings...")
        url = urljoin(self.url, "SNMP.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read SNMP page: {ex}")
            return {}

        snmp_settings = {}

        # TODO: parse SNMP settings and put into data model
        # self.dump_htmltable(response, snmp_settings)

        dev.extra["snmp_settings"] = snmp_settings
        return {"snmp_settings": snmp_settings}

    def gateway_port_settings(self, dev: DeviceData) -> dict:
        """
        Get serial port settings (``SerialPortSettings.sel``).
        """
        self.log.info("Getting serial port settings...")
        url = urljoin(self.url, "SerialPortSettings.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read port settings page: {ex}")
            return {}

        port_settings = {}

        # TODO: parse serial port settings and put into data model
        # self.dump_htmltable(response, port_settings)

        dev.extra["port_settings"] = port_settings
        return {"port_settings": port_settings}

    def gateway_port_profiles(self, dev: DeviceData) -> dict:
        """
        Get serial port profiles (``SerialPortProfiles.sel``).
        """
        self.log.info("Getting serial port profiles...")
        url = urljoin(self.url, "SerialPortProfiles.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to port profiles page: {ex}")
            return {}

        port_profiles = {}

        # TODO: parse serial port profiles and put into data model
        # self.dump_htmltable(response, port_profiles)

        dev.extra["port_profiles"] = port_profiles
        return {"port_profiles": port_profiles}

    def gateway_port_mappings(self, dev: DeviceData) -> dict:
        """
        Get port mappings (``PortMappings.sel``).
        """
        self.log.info("Getting port mappings...")
        url = urljoin(self.url, "PortMappings.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to port mappings page: {ex}")
            return {}

        port_mappings = {}

        # TODO: parse port mappings and put into data model
        # self.dump_htmltable(response, port_mappings)

        dev.extra["port_mappings"] = port_mappings
        return {"port_mappings": port_mappings}

    def gateway_ipsec(self, dev: DeviceData) -> dict:
        """
        Get IPSec connections (``IPsec.sel``).
        """
        self.log.info("Getting IPSec connections...")
        url = urljoin(self.url, "IPsec.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read IPsec page: {ex}")
            return {}

        ipsec = {}

        # TODO: parse ipsec connections and put into data model
        # self.dump_htmltable(response, ipsec)

        dev.extra["ipsec"] = ipsec
        return {"ipsec": ipsec}

    def gateway_macsec(self, dev: DeviceData) -> dict:
        """
        Get MACSec connections (``MACsec.sel``).
        """
        self.log.info("Getting MACSec connections...")
        url = urljoin(self.url, "MACsec.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read MACsec page: {ex}")
            return {}

        macsec = {}

        # TODO: parse macsec connections and put into data model
        # self.dump_htmltable(response, macsec)

        dev.extra["macsec"] = macsec
        return {"macsec": macsec}

    def gateway_allowed_clients(self, dev: DeviceData) -> dict:
        """
        Get Allowed Clients (``AllowedClients.sel``).
        """
        self.log.info("Getting Allowed Clients...")
        url = urljoin(self.url, "AllowedClients.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read Allowed Clients page: {ex}")
            return {}

        allowed_clients = {}

        # TODO: parse allowed clients and put into data model
        # self.dump_htmltable(response, allowed_clients)

        dev.extra["allowed_clients"] = allowed_clients
        return {"allowed_clients": allowed_clients}

    def gateway_sshkey(self, dev: DeviceData) -> dict:
        """
        Get SSH Host Keys (``SSH_Host_Key.sel``).
        """
        self.log.info("Getting SSH Host Key...")
        url = urljoin(self.url, "SSH_Host_Key.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read SSH Host Key page: {ex}")
            return {}

        ssh_host_key = {}

        # TODO: parse gateway SSH keys and put into data model
        # self.dump_htmltable(response, ssh_host_key)

        dev.extra["ssh_host_key"] = ssh_host_key
        return {"ssh_host_key": ssh_host_key}

    def gateway_password_management(self, dev: DeviceData) -> dict:
        """
        Get password management messages (``PasswordManagement.sel``).
        """
        self.log.info("Getting password management messages...")
        url = urljoin(self.url, "PasswordManagement.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read Password Management page: {ex}")
            return {}

        password_management = {}

        # TODO: parse password management messages and put into data model
        # self.dump_htmltable(response, password_management)

        dev.extra["password_management"] = password_management
        return {"password_management": password_management}

    def gateway_system_logs(self, dev: DeviceData) -> dict:
        """
        Get system logs (``SysLogReport.sel``).
        """
        self.log.info("Getting gateway system logs...")
        url = urljoin(self.url, "SysLogReport.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read system logs page: {ex}")
            return {}

        soup = self.gen_soup(response.content)
        table = soup.find("table", id="syslogReport")
        rows = list(table.find_all("tr"))
        raw_logs = []

        # skip first row, it has UI elements for sorting, etc.
        for row in reversed(rows[1:]):
            # recvTime, tag, severity, facility, msg
            e_data = {
                col["class"][0]: col.get_text()
                for col in row.find_all("td")
                if col["class"][0] != "actions"
            }
            e_data["id"] = row["id"].split("_")[-1]  # id='id_######'
            raw_logs.append(e_data)

            event = Event(
                created=utils.parse_date(e_data["recvTime"]),
                dataset="gateway_system_logs",
                id=e_data["id"],
                message=e_data["msg"].strip(),
                original=e_data["msg"],
                provider=dev.name if dev.name else dev.get_id(),
                sequence=int(e_data["id"]),
                severity=e_data["severity"],
                extra={
                    "tag": e_data["tag"],
                    "facility": e_data["facility"],
                },
            )
            dev.store("event", event)

        dev.write_file(raw_logs, "gateway-system-logs.json")

        return {"gateway_system_logs": raw_logs}

    def gateway_diagnostics(self, dev: DeviceData) -> dict:
        """
        Get diagnostic data from SEL gateway (``Diagnostics.sel``).
        """

        self.log.info("Getting gateway diagnostic data...")
        url = urljoin(self.url, "Diagnostics.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()

            if not response or not response.content:
                self.log.warning("Failed to read Diagnostics page")
                return {}
        except Exception as ex:
            self.log.warning(f"Failed to read Diagnostics page: {ex}")
            return {}

        gateway_diagnostics = {}
        # TODO: parse gateway diagnostics and put into data model
        # self.dump_htmltable(response, gateway_diagnostics)

        dev.extra["gateway_diagnostics"] = gateway_diagnostics
        return {"gateway_diagnostics": gateway_diagnostics}

    def gateway_proxy_reports(self, dev: DeviceData) -> dict:
        """
        Get proxy reports from ``ProxyReports.sel``.
        """
        self.log.info("Getting proxy reports from gateway...")
        url = urljoin(self.url, "ProxyReports.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read proxy reports Key page: {ex}")
            return {}

        # TODO: generate and download reports
        # commands and devices
        # password updates
        # Managed Device Passwords
        # Password Change Log

        proxy_reports = {}

        dev.extra["proxy_reports"] = proxy_reports
        return {"proxy_reports": proxy_reports}

    def gateway_cert_export(self, dev: DeviceData) -> dict:
        """
        Export X509 certificates from  (``x509.sel``).
        """
        self.log.info("Downloading X509 certificates from gateway...")
        url = urljoin(self.url, "X509.sel")

        response = self.post(url, data=self._rando, dev=dev, use_cache=True)
        response.raise_for_status()

        # Grab the export pages containing all X509 certs listed on the X509 main page
        soup = BeautifulSoup(response._content, "html.parser")
        view_links = [
            link["href"]
            for link in soup.find_all("a", class_="listButton")
            if link.text.strip() == "Export"
        ]
        view_pages = [href.split("https://")[0] for href in view_links]

        x509_cert_export = {}
        for href in view_pages:
            # A 5-second timeout sometimes fails, device can be slow
            cert_url = urljoin(self.url, href)
            response = self.post(cert_url, data=self._rando, dev=dev, timeout=17.0)

            if not response or response.status_code != 200:
                self.log.warning(f"Failed to download certificate from {cert_url}")
                continue

            decoded, raw = self.decode_ssl_certificate(response.text)
            x509_obj = self.parse_decoded_ssl_certificate(decoded, raw)

            # If filename was extracted from response, use that as the key
            # to the dict.
            dict_key = href
            if response.file_path:
                dict_key = response.file_path.name
                dev.related.files.add(dict_key)

            x509_obj.annotate(dev)
            x509_cert_export[dict_key] = x509_obj.dict()

        dev.extra["x509_certificates"] = x509_cert_export
        return {"x509_certificates": x509_cert_export}

    # -------------------- End of gateway web pages --------------------


def querystr() -> str:
    return f"asfdasfowefsj={utils.utc_now()}"  # NOTE: this was previously datetime.utcnow()


def parse_simple_table(table_start: str, table_end: str, page_data: str) -> dict:
    try:
        regex = rf"{table_start}:\n([\s\S]+){table_end}"
        data = re.findall(regex, page_data)[0].split("\n")
        table_data = [
            re.findall(r"\s+([^=|:]+)[=|:]\s+(.+)", line)[0] for line in data if line
        ]
        return {v[0]: v[1] for v in table_data}
    except IndexError:
        log.warning(
            f"Failed parse_simple_table\nTable start: '{table_start}'\n"
            f"Table end: '{table_end}'\nRaw data: {repr(page_data)}\n"
        )
        return {}


def parse_simple_list(list_start: str, list_end: str, page_data: str) -> list[str]:
    try:
        regex = rf"{list_start}:\n([\s\S]+){list_end}"
        data = re.findall(regex, page_data)[0].split("\n")
        return [line.strip() for line in data if line]
    except IndexError:
        log.warning(
            f"Failed parse_simple_list\nList start: '{list_start}'\n"
            f"List end: '{list_end}'\nRaw data: {repr(page_data)}\n"
        )
        return []


def parse_multiple_lists(page_data: str) -> dict:
    try:
        settings = page_data.split("\n\n")
        parsed = {}
        for x in range(0, len(settings), 2):
            list_name = settings[x].strip()
            data = re.findall(r"(\S*)\s*:=(.+?(?=\s\s|\n))", settings[x + 1] + "\n")
            if len(data) > 0:
                parsed[list_name] = {v[0]: v[1].lstrip().replace('"', "") for v in data}
        return parsed
    except IndexError:
        log.warning(f"Failed parse_multiple_lists\nRaw data: {repr(page_data)}\n")
        return {}


def parse_simple_line(param_name: str, page_data: str) -> str:
    if param_name not in page_data:
        log.warning(f"Failed parse_simple_line: param '{param_name}' not in page")
        return ""
    try:
        return re.findall(rf"\n\s*{param_name}[=|:]\s*(\S+)", page_data)[0]
    except IndexError:
        log.warning(
            f"Failed parse_simple_line\nParam name: '{param_name}'\n"
            f"Raw data: {repr(page_data)}\n"
        )
        return ""


def normalize_keys(obj: dict) -> dict:
    """
    Convert dictionary keys to lowercase underscore-separated.
    """
    return {key.strip().lower().replace(" ", "_"): value for key, value in obj.items()}


def parse_comments(obj: dict) -> dict:
    """
    Split value strings with comments into the value and the comment.
    """
    results = {}

    for name, value in obj.items():
        parts = value.split("#")
        results[name] = {
            "value": parts[0].strip(),
            "comment": parts[1].strip() if len(parts) > 1 else "",
        }

    return results


def read_html(content: str | bytes) -> dict[str, str]:
    """
    Replace functionality of the Pandas HTML parser.
    """

    soup = BeautifulSoup(content, features=consts.BS4_PARSER)

    table = soup.find("table")
    if not table:
        return {}

    unknown_i = 0
    data = {}

    # Find rows in html table objects
    for row in table.find_all("tr"):
        if not row:
            continue

        # Find columns in each row
        col = row.find_all("td")
        if len(col) < 2:
            continue

        # Row Label
        # '<td class="firstColumn">Host Name:</td>' => "Host Name"
        name = clean_text(col[0].get_text())

        # handle case where empty string as key
        if not name:
            name = f"Unknown_{unknown_i}"
            unknown_i += 1

        if len(col) == 2:
            data[name] = clean_text(col[1].get_text())

            # Some cells have a <input/> tag as their value, instead of the text
            # These fields are designed to take user input, and provide the current
            # value in the "value" attribute.
            if not data[name] and col[1].contents:
                input_tag = col[1].find("input")

                # We don't care about other tag types for now,
                # they may be things like links to other pages.
                if not input_tag:
                    continue

                # Current value
                if input_tag.attrs.get("value"):
                    data[name] = clean_text(input_tag.attrs["value"])

                # Checkbox fields
                elif input_tag.attrs.get("type", "") == "checkbox":
                    # boolean, if attr named "checked", then true, else false
                    if "checked" in input_tag.attrs:
                        data[name] = "true"
                    else:
                        data[name] = "false"
        else:
            # Iterate over columns
            data[name] = []
            for pos in col[1:]:
                data[name].append(clean_text(pos.get_text()))

    return data


def clean_text(data: str) -> str:
    """
    Attempt to remove whitespace and new line characters.
    """
    return data.replace("\\\\n", "").replace("\\n", "").lstrip().rstrip()


__all__ = ["SELHTTP"]
